use super::encoding::date_format;
use chrono::{DateTime, FixedOffset};
use serde_derive::{Deserialize, Serialize};

use crate::license::lcp_license::Link;

#[derive(Debug, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "lowercase")]
enum Status {
    #[default]
    Ready,
    Active,
    Revoked,
    Returned,
    Cancelled,
    Expired,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "lowercase")]
enum EventType {
    #[default]
    Register,
    Renew,
    Return,
    Revoke,
    Cancel,
}

/// Timestamps associated with the license and status document.
#[derive(Debug, Serialize, Deserialize, PartialEq, Default)]
pub struct Updated {
    /// Time and Date when the License Document was last updated.
    #[serde(with = "date_format")]
    license: DateTime<FixedOffset>,
    /// Time and Date when the Status Document was last updated.
    #[serde(with = "date_format")]
    status: DateTime<FixedOffset>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Default)]
pub struct PotentialRights {
    /// Time and Date when the license ends.
    #[serde(with = "date_format")]
    end: DateTime<FixedOffset>,
}

/// Events related to the change in status of a License Document.
#[derive(Debug, Serialize, Deserialize, PartialEq, Default)]
pub struct Event {
    /// Identifies the type of event.
    #[serde(rename = "type")]
    event_type: EventType,
    /// Name of the client, as provided by the client during an interaction.
    name: String,
    /// Identifies the client, as provided by the client during an interaction.
    id: String,
    /// Time and date when the event occurred.
    #[serde(with = "date_format")]
    timestamp: DateTime<FixedOffset>,
}

/// Document that contains information about the history of a License Document, along with
/// its current status and available interactions.
#[derive(Debug, Serialize, Deserialize, PartialEq, Default)]
pub struct LicenseStatus {
    /// Unique identifier for the License Document associated to the Status Document
    id: String,
    /// Describes the current status of the license
    status: Status,
    /// A message meant to be displayed to the User regarding the current status of the license.
    message: String,
    /// Data and time when the status and associated license were updated.
    updated: Updated,
    #[serde(skip_serializing_if = "Option::is_none")]
    potential_rights: Option<PotentialRights>,
    links: Vec<Link>,
    events: Vec<Event>,
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::license::status::LicenseStatus;

    #[test]
    fn test_decode() {
        let json = json!(
            {
              "id": "234-5435-3453-345354",
              "status": "active",
              "message": "Your license is currently active and has been used on one device.",

              "updated": {
                "license": "2016-08-05T00:00:00Z",
                "status": "2016-08-08T00:00:00Z"
              },

              "links": [
                {
                  "rel": "license",
                  "href": "https://example.org/license/35d9b2d6",
                  "type": "application/vnd.readium.lcp.license.v1.0+json",
                  "profile": "http://readium.org/lcp/basic-profile"
                },
                {
                  "rel": "register",
                  "href": "https://example.org/license/35d9b2d6/register{?id,name}",
                  "type": "application/vnd.readium.license.status.v1.0+json",
                  "templated": true
                },
                {
                  "rel": "return",
                  "href": "https://example.org/license/35d9b2d6/return{?id,name}",
                  "type": "application/vnd.readium.license.status.v1.0+json",
                  "templated": true
                },
                {
                  "rel": "renew",
                  "href": "https://example.org/license/35d9b2d6/renew{?end,id,name}",
                  "type": "application/vnd.readium.license.status.v1.0+json",
                  "templated": true
                }
              ],

              "potential_rights": {
                "end": "2014-09-13T00:00:00Z"
              },

              "events": [
                {
                  "type": "register",
                  "name": "eBook App (Android)",
                  "timestamp": "2016-07-14T00:00:00Z",
                  "id": "709e1380-3528-11e5-a2cb-0800200c9a66"
                }
              ]
            }
        );
        let status: LicenseStatus = serde_json::from_value(json).unwrap();
        dbg!(status);
    }

    #[test]
    fn roundtrip() {
        let a = LicenseStatus::default();
        let serialized = serde_json::to_value(&a).unwrap();
        let b = serde_json::from_value(serialized).unwrap();

        assert_eq!(a, b);
    }
}
