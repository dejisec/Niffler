use std::fmt;

use clap::ValueEnum;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum Triage {
    Green = 0,
    Yellow = 1,
    Red = 2,
    Black = 3,
}

impl fmt::Display for Triage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Green => write!(f, "Green"),
            Self::Yellow => write!(f, "Yellow"),
            Self::Red => write!(f, "Red"),
            Self::Black => write!(f, "Black"),
        }
    }
}
