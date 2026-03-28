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

#[cfg(test)]
mod tests {
    use std::cmp::max;

    use super::*;

    #[test]
    fn triage_ordering() {
        assert!(Triage::Green < Triage::Yellow);
        assert!(Triage::Yellow < Triage::Red);
        assert!(Triage::Red < Triage::Black);
    }

    #[test]
    fn triage_equality() {
        assert_eq!(Triage::Black, Triage::Black);
        assert_ne!(Triage::Green, Triage::Red);
    }

    #[test]
    fn triage_display() {
        assert_eq!(Triage::Black.to_string(), "Black");
        assert_eq!(Triage::Red.to_string(), "Red");
        assert_eq!(Triage::Yellow.to_string(), "Yellow");
        assert_eq!(Triage::Green.to_string(), "Green");
    }

    #[test]
    fn triage_max_selects_higher_severity() {
        assert_eq!(max(Triage::Green, Triage::Red), Triage::Red);
        assert_eq!(max(Triage::Black, Triage::Yellow), Triage::Black);
    }
}
