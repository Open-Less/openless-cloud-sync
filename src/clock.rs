use crate::error::{ApiError, Result};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

pub(crate) fn now() -> i64 {
    OffsetDateTime::now_utc().unix_timestamp()
}

pub(crate) fn wire_timestamp(seconds: i64) -> Result<String> {
    OffsetDateTime::from_unix_timestamp(seconds)
        .map_err(|_| ApiError::unavailable())?
        .format(&Rfc3339)
        .map_err(|_| ApiError::unavailable())
}

pub(crate) fn parse_rfc3339(value: &str) -> Result<i64> {
    OffsetDateTime::parse(value, &Rfc3339)
        .map(OffsetDateTime::unix_timestamp)
        .map_err(|_| ApiError::unavailable())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_v1_utc_seconds_encoding_and_numeric_offset_expiry() {
        let legacy = "2026-09-23T00:00:00Z";
        let seconds = parse_rfc3339(legacy).unwrap();
        assert_eq!(wire_timestamp(seconds).unwrap(), legacy);
        assert_eq!(
            parse_rfc3339("2026-09-23T03:00:00.999999999+03:00").unwrap(),
            seconds
        );
        assert_eq!(parse_rfc3339("1970-01-01T00:00:00Z").unwrap(), 0);
        assert_eq!(wire_timestamp(-1).unwrap(), "1969-12-31T23:59:59Z");
        assert!(parse_rfc3339("2026-09-23T00:00:00").is_err());
    }
}
