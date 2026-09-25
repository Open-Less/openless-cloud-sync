# 加密数据协议 v1

状态：合同版本 `1.0-draft.1`；[固定测试向量](../tests/vectors/v1.json) 已由 RustCrypto 与 reference Argon2/libsodium 验证。客户端接入与跨设备验收仍待完成。本文定义字节级互操作要求。HTTP 字段见 [API](http-api.md)；机器定义见 [OpenAPI](openapi.yaml)。

## 1. 固定密码学配置

| 项 | v1 唯一接受值 |
| --- | --- |
| `cryptoProfile` | `argon2id-xchacha20poly1305-v1` |
| KDF | Argon2id，版本 `0x13`（JSON 为十进制 `19`） |
| 参数 | `memoryKiB=65536`、`iterations=3`、`parallelism=4`、输出 32 字节 |
| 盐 | 创建加密库或改密码时由设备 CSPRNG 生成 16 字节；普通快照沿用当前盐 |
| AEAD | `xchacha20poly1305-ietf`，32 字节密钥、24 字节 nonce、16 字节认证标签 |
| nonce | 每份新请求独立 CSPRNG 生成；同密钥不得复用。网络重试复用原请求的完整字节，而非重新加密。 |
| 二进制文本编码 | RFC 4648 base64url，无 `=` 填充，拒绝非规范形式 |
| 私有内容编码 | `json-pad64k-v1`，下文定义；v1 不压缩含密钥的数据 |

Argon2 参数采用 RFC 9106 面向较低内存环境的推荐配置；实现必须运行官方测试向量。[RFC 9106 §4、§7.4](https://www.rfc-editor.org/rfc/rfc9106.html#section-7.4)

XChaCha20-Poly1305 使用扩展 nonce 支持各设备独立生成随机 nonce，采用 combined 模式把认证标签附加在密文末尾。不要混用 12 字节 nonce 的另一种 ChaCha20-Poly1305 构造。[libsodium 官方说明](https://doc.libsodium.org/secret-key_cryptography/aead/chacha20-poly1305/xchacha20-poly1305_construction)

不得接收服务端建议的更低 KDF 成本、未知算法或自定义参数。读取头部后先检查固定参数、长度和限额，再分配内存或执行 KDF；新算法必须使用新协议版本，不能静默降级。

## 2. 密码字节与本机密钥

1. 输入密码先进行 Unicode NFC 规范化，再按 UTF-8 编码；不自动 trim，不改变大小写。
2. 规范化后为 12–128 个 Unicode scalar value，UTF-8 不超过 512 字节；包含至少一个 `[0-9]`、一个 `[A-Z]` 和一个 `[a-z]`。确认密码按规范化后的 UTF-8 字节比较。
3. 客户端本地拒绝常见密码及明显序列/重复变体，包含 `12345678`、`Password123`、`Password1234`、`Abc123456789`、`Qwerty123456` 等回归样本。阻止名单与检查版本随客户端发布，候选密码不能送往远端评分或校验。
4. `encryptionKey = Argon2id(passwordUtf8, salt, m=65536 KiB, t=3, p=4, out=32)`。不增加隐藏 pepper，不截断密码，不先做不可见的 SHA 哈希。
5. 密码仅为解锁操作的短期输入，不能写入日志、偏好、快照或崩溃附加信息。派生密钥只在受控内存及用户允许的本机系统安全存储中存在；结束使用时尽可能清除。
6. 安全存储的绑定至少包括 `serviceOrigin + ownerGithubId + vaultId + keyId`。不能让 A 账号的密钥用于 B 账号，或让测试服务密钥解锁正式服务。

字符组合是产品规则，不代表给密码赋予确定的熵。阻止常见弱密码和提高派生成本是不同保护；服务器不接收密码，因此不能独立强制客户端的密码强度策略。[OWASP 密码存储建议](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)

## 3. 解密后的逻辑快照

顶层 UTF-8 JSON 对象：

| 字段 | 类型 | 约束 |
| --- | --- | --- |
| `schemaVersion` | integer | `1` |
| `exportedAt` | string | RFC3339 UTC；只展示，不用作冲突胜负依据 |
| `sourceDevice` | object | 加密的设备 ID、系统、架构和应用版本 |
| `documents` | array | 每条 `{id, kind, schemaVersion, value}`；同 kind/id 唯一 |
| `tombstones` | array | 每条 `{id, kind, deletedAt, baseRevision}`；同一文档不能同时存在于 documents 与 tombstones |

`id` 是逻辑 ID，不是文件路径。`kind` 只允许：`preferences`、`ui_preferences`、`channels`、`provider_credentials`、`dictionary`、`vocabulary_presets`、`corrections`、`style_packs`、`history`、`activity`、`device_profile`。每个 kind 的具体映射由 [客户端交接](client-integration.md) 的登记表定义，不能由服务器指定写入本机任意路径。

凭据文档必须包含渠道 ID、命名空间和逻辑账户键；完整服务密钥只存在于该加密对象内。图片内容按登记格式保存，不包含磁盘绝对路径。设备相关路径只作为 `device_profile` 数据保留，不能自动执行其指向的程序。

客户端必须保留本协议内未知的配置键，用受控的扩展存储往返；未知 kind 或不支持的文档 schemaVersion 则停止应用整份快照并提示升级。禁止“成功恢复”后把不认识的数据重新上传为空。v1 不自动回收删除标记，以防长期离线设备复活已删内容。

## 4. 明文 framing 与限额

- JSON 最大 **15 MiB（15,728,640 字节）**。拒绝重复 JSON key、非法 UTF-8、非有限数值和深度超过 64 的嵌套；documents+tombstones 合计最多 100,000 条。超过限额不截断。
- 构造 `plaintext = uint32_be(jsonByteLength) || jsonUtf8 || randomPadding`。
- 补齐至 65,536 字节的整数倍，最少一块；填充字节来自 CSPRNG，解密后按前四字节长度取 JSON，忽略剩余填充。
- padded plaintext 最多 16 MiB；combined ciphertext 最多 **16,777,232 字节**（包含 16 字节标签）。请求/响应 JSON 总体最多 **24 MiB**。
- 不压缩：避免把用户服务密钥和可受外部影响的文本放入同一个压缩长度侧信道。填充降低精细长度暴露，不隐藏账号、访问时间或大致数据量。

所有限额同时作用于导出和恢复；服务端验证密文字节与 HTTP 体积，客户端验证解密后格式和逻辑内容。不能在认证标签验证成功前解析或应用明文。

## 5. 加密头与 AAD

`SnapshotUpload` 中的头部字段包括：`protocolVersion`、`payloadSchemaVersion`、`ownerGithubId`、`vaultId`、`keyId`、`baseRevision`、`revision`、`operationId`、`kind`、`cryptoProfile`、`kdf`、`aead`、`codec`、`nonce`。完整字段类型和约束在 OpenAPI 中。

其中 revision 为规范的十进制字符串，不能转换成 JavaScript 浮点数；`revision = baseRevision + 1`。vault ID、key ID、operation ID 均为 CSPRNG 生成的小写 UUIDv4。

AAD 是以下**有序数组**的紧凑 JSON UTF-8 字节；不加空白或 BOM，不转成 JSON 对象。所有 ID/revision/salt 均为 ASCII 规范字符串，固定数字按下列十进制形式序列化：

```json
["openless-cloud-sync",1,"snapshot","OWNER_GITHUB_ID","VAULT_ID","KEY_ID","BASE_REVISION","REVISION","OPERATION_ID","KIND",1,"argon2id-xchacha20poly1305-v1","argon2id",19,65536,3,4,"SALT_BASE64URL","xchacha20poly1305-ietf","json-pad64k-v1"]
```

大写占位符替换为对应字段值；第 11 项是 `payloadSchemaVersion`。`nonce` 按解码后的 24 字节传入 AEAD，密文采用 combined 格式。数组顺序是协议的一部分。

解密前验证：账号 ID 与本次认证账号一致，vault/key ID 与读取的元信息一致，版本与此次读取绑定，固定参数全部匹配。将任何字段从另一个账号、加密库、密码代次或版本移植过来都必须失败。

`ciphertextSha256` 是 **combined ciphertext 解码后的 SHA-256**，仅用于传输、幂等和版本核对；不是明文哈希。不得向服务器发送密码哈希、明文内容哈希、私有字段名称或数据条数。

## 6. 创建、普通写入与改密码

| `kind` | 必须满足 |
| --- | --- |
| `create` | 元信息为 empty，或用户已明确同意在 deleted 状态重新建库；新 vault ID、新 key ID、新盐、新 nonce。服务端版本继续递增，不归零。 |
| `snapshot` | 沿用当前 vault ID、key ID、盐和固定配置；新 operation ID、新 nonce；以最新基线合并后上传完整快照。 |
| `password_change` | 已验证当前密码；保持 vault ID，生成新的 key ID、盐、nonce，用新密码派生新密钥，完整重新加密。快照替换与密码代次变化必须在同一成功操作中出现。 |

上传每次使用 CAS；改密码失败或结果未知时保留旧、新密钥的受保护操作状态，先核对 operation receipt，再决定使用哪一个。不能先删旧本机密钥，再发现服务器未收到新密文。

其他设备遇到新的 key ID 后，停止旧密钥的待上传动作并进入 `locked`，保留自己的未同步数据。用户用新密码解锁后重新读取、合并再上传；不能拿旧盐/旧 key ID 重新覆盖服务器的新密码代次。

## 7. 能防什么、不能宣称什么

- 按本协议正确实现时，单独取得云端密文或同步访问令牌不等于取得解密密码；服务器不应拥有明文恢复能力。
- GitHub 账号被接管仍可能导致云端密文被删除或替换；客户端不得把验证失败的内容覆盖本机。设备感染、弱密码和解锁状态内存泄露不由云端加密消除。
- 客户端记录每个账号/vault 已接受的最高版本，拒绝回退；服务端向全新设备重放其从未见过的旧有效版本，不能仅靠本协议证明最新性。不得对外声称已解决恶意服务器的全部回滚问题。
- 备份、错误诊断和运营工具必须保持同一密文边界；“已加密”不能替代认证隔离、版本校验、限额和本地恢复验证。

## 8. 接手实现必须交付的互操作样本

在代码实现阶段交付固定、公开的测试向量文件，包含：规范化密码输入、盐、nonce、账号/vault/key/revision、AAD 的 UTF-8 十六进制、派生密钥、padding 固定样本、combined ciphertext 与恢复 JSON。测试值不得用于生产随机数。

至少两个独立实现生成/验证同一向量，并覆盖中文/组合字符密码、跨设备、篡改头部、错密码、错误 nonce 长度、AAD 字段调序、截断标签、非规范 base64、padding 长度伪造与最大体积。仅靠单实现“自己加密再自己解密”不满足验收。
