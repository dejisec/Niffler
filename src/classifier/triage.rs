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
            Triage::Green => write!(f, "Green"),
            Triage::Yellow => write!(f, "Yellow"),
            Triage::Red => write!(f, "Red"),
            Triage::Black => write!(f, "Black"),
        }
    }
}
