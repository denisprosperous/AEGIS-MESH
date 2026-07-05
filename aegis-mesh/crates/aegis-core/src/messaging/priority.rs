//! Priority levels (audit fix: validate range, document Emergency behavior).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Priority {
    Emergency = 0,
    High = 1,
    Normal = 2,
    Low = 3,
    Bulk = 4,
}

impl Default for Priority { fn default() -> Self { Self::Normal } }

impl Priority {
    pub fn as_u8(self) -> u8 { self as u8 }
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0 => Self::Emergency, 1 => Self::High, 2 => Self::Normal, 3 => Self::Low, 4 => Self::Bulk,
            _ => return None,
        })
    }
}
