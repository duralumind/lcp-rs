pub mod date_format {
    use chrono::{DateTime, FixedOffset};
    use serde::{self, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(val: &DateTime<FixedOffset>, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let date_time_str = val.to_rfc3339();
        date_time_str.serialize(s)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<DateTime<FixedOffset>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let date_time_str: String = serde::de::Deserialize::deserialize(deserializer)?;
        DateTime::parse_from_rfc3339(&date_time_str)
            .map_err(|e| serde::de::Error::custom(format!("{:?}", e)))
    }
}

pub mod optional_date_format {
    use chrono::{DateTime, FixedOffset};
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(val: &Option<DateTime<FixedOffset>>, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match val {
            Some(dt) => super::date_format::serialize(dt, s),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<DateTime<FixedOffset>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Option::<String>::deserialize(deserializer)?
            .map(|s| {
                DateTime::parse_from_rfc3339(&s)
                    .map_err(|e| serde::de::Error::custom(format!("{:?}", e)))
            })
            .transpose()
    }
}

pub mod certificate_format {
    use base64::{Engine, engine::general_purpose};
    use serde::{self, Deserialize, Deserializer, Serializer};
    use x509_cert::{
        Certificate,
        der::{Decode, Encode},
    };

    pub fn serialize<S>(certificate: &Certificate, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let der_bytes = certificate.to_der().map_err(|e| {
            serde::ser::Error::custom(format!("Failed to encode certificate: {}", e))
        })?;
        let base64_string = general_purpose::STANDARD.encode(&der_bytes);
        serializer.serialize_str(&base64_string)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Certificate, D::Error>
    where
        D: Deserializer<'de>,
    {
        let base64_string: String = String::deserialize(deserializer)?;
        let der_bytes = general_purpose::STANDARD
            .decode(&base64_string)
            .map_err(|e| serde::de::Error::custom(format!("Failed to decode base64: {}", e)))?;
        Certificate::from_der(&der_bytes)
            .map_err(|e| serde::de::Error::custom(format!("Failed to parse certificate: {}", e)))
    }
}
