use argon2::{Algorithm, Argon2, Params, ParamsBuilder, Version};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use openless_cloud_sync::protocol::{Snapshot, decode, hash};
use serde_json::Value;
use unicode_normalization::UnicodeNormalization;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn framed_json(plaintext: &[u8]) -> Result<Value, &'static str> {
    if plaintext.is_empty() || plaintext.len() > 16777216 || !plaintext.len().is_multiple_of(65536)
    {
        return Err("invalid padding");
    }
    let size = u32::from_be_bytes(plaintext[..4].try_into().unwrap()) as usize;
    if size > 15728640 || size + 4 > plaintext.len() {
        return Err("invalid length");
    }
    serde_json::from_slice(&plaintext[4..size + 4]).map_err(|_| "invalid JSON")
}

#[test]
fn rfc9106_official_argon2id_vector() {
    let mut builder = ParamsBuilder::new();
    builder
        .m_cost(32)
        .t_cost(3)
        .p_cost(4)
        .output_len(32)
        .data((&[4u8; 12][..]).try_into().unwrap());
    let params = builder.build().unwrap();
    let argon =
        Argon2::new_with_secret(&[3u8; 8], Algorithm::Argon2id, Version::V0x13, params).unwrap();
    let mut key = [0u8; 32];
    argon
        .hash_password_into(&[1u8; 32], &[2u8; 16], &mut key)
        .unwrap();
    assert_eq!(
        key.to_vec(),
        unhex("0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659")
    );
}

#[test]
fn rustcrypto_matches_independent_argon2_and_libsodium_vectors() {
    let fixture: Value = serde_json::from_str(include_str!("vectors/v1.json")).unwrap();
    for vector in fixture["vectors"].as_array().unwrap() {
        let snapshot: Snapshot = serde_json::from_value(vector["snapshot"].clone()).unwrap();
        snapshot.validate("12345").unwrap();
        let normalized = vector["passwordInput"]
            .as_str()
            .unwrap()
            .nfc()
            .collect::<String>();
        assert_eq!(normalized, vector["passwordNfc"].as_str().unwrap());
        assert_eq!(
            normalized.as_bytes(),
            unhex(vector["passwordUtf8Hex"].as_str().unwrap())
        );
        let mut key = [0u8; 32];
        let argon = Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(65536, 3, 4, Some(32)).unwrap(),
        );
        let salt = decode(&snapshot.kdf.salt, Some(16)).unwrap();
        argon
            .hash_password_into(normalized.as_bytes(), &salt, &mut key)
            .unwrap();
        assert_eq!(
            key.to_vec(),
            unhex(vector["derivedKeyHex"].as_str().unwrap())
        );
        let aad = snapshot.aad();
        assert_eq!(aad, unhex(vector["aadUtf8Hex"].as_str().unwrap()));
        let nonce = decode(&snapshot.nonce, Some(24)).unwrap();
        let nonce = XNonce::from_slice(&nonce);
        let ciphertext = decode(&snapshot.ciphertext, None).unwrap();
        let cipher = XChaCha20Poly1305::new_from_slice(&key).unwrap();
        let plaintext = cipher
            .decrypt(
                nonce,
                Payload {
                    msg: &ciphertext,
                    aad: &aad,
                },
            )
            .unwrap();
        assert_eq!(framed_json(&plaintext).unwrap(), vector["recoveredJson"]);
        let json = unhex(vector["plaintextJsonUtf8Hex"].as_str().unwrap());
        let mut expected = (json.len() as u32).to_be_bytes().to_vec();
        expected.extend_from_slice(&json);
        let padding = (0..vector["padding"]["length"].as_u64().unwrap())
            .map(|i| (i % 251) as u8)
            .collect::<Vec<_>>();
        assert_eq!(
            hash(&padding),
            vector["padding"]["sha256"].as_str().unwrap()
        );
        expected.extend_from_slice(&padding);
        assert_eq!(plaintext, expected);
        assert_eq!(
            cipher
                .encrypt(
                    nonce,
                    Payload {
                        msg: &expected,
                        aad: &aad
                    }
                )
                .unwrap(),
            ciphertext
        );

        for field in [
            "ownerGithubId",
            "vaultId",
            "keyId",
            "baseRevision",
            "revision",
            "operationId",
            "kind",
        ] {
            let mut bad = vector["snapshot"].clone();
            bad[field] = if field == "kind" {
                "create".into()
            } else {
                format!("{}x", bad[field].as_str().unwrap()).into()
            };
            let modified: Snapshot = serde_json::from_value(bad).unwrap();
            assert!(
                cipher
                    .decrypt(
                        nonce,
                        Payload {
                            msg: &ciphertext,
                            aad: &modified.aad()
                        }
                    )
                    .is_err(),
                "{field}"
            );
        }
        let mut aad_array: Vec<Value> = serde_json::from_slice(&aad).unwrap();
        aad_array.swap(3, 4);
        assert!(
            cipher
                .decrypt(
                    nonce,
                    Payload {
                        msg: &ciphertext,
                        aad: &serde_json::to_vec(&aad_array).unwrap()
                    }
                )
                .is_err()
        );
        assert!(
            cipher
                .decrypt(
                    nonce,
                    Payload {
                        msg: &ciphertext[..ciphertext.len() - 1],
                        aad: &aad
                    }
                )
                .is_err()
        );
        let mut altered = ciphertext.clone();
        altered[20] ^= 1;
        assert!(
            cipher
                .decrypt(
                    nonce,
                    Payload {
                        msg: &altered,
                        aad: &aad
                    }
                )
                .is_err()
        );
        let mut wrong_key = [0u8; 32];
        argon
            .hash_password_into(b"WrongPassword2026!", &salt, &mut wrong_key)
            .unwrap();
        assert!(
            XChaCha20Poly1305::new_from_slice(&wrong_key)
                .unwrap()
                .decrypt(
                    nonce,
                    Payload {
                        msg: &ciphertext,
                        aad: &aad
                    }
                )
                .is_err()
        );
        let mut forged = plaintext.clone();
        forged[..4].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(framed_json(&forged).is_err());
        assert!(decode(&(snapshot.kdf.salt.clone() + "="), Some(16)).is_err());
        assert!(decode(&snapshot.nonce, Some(12)).is_err());
    }
}
