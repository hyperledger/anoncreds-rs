use chrono::{DateTime, Timelike, Utc};

pub fn today() -> DateTime<Utc> {
    Utc::now()
        .with_hour(0)
        .and_then(|issuance_date| issuance_date.with_minute(0))
        .and_then(|issuance_date| issuance_date.with_second(0))
        .and_then(|issuance_date| issuance_date.with_nanosecond(0))
        .unwrap_or_default()
}