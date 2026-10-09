//! Reports distinguish converged changes, unavailable operations and audit evidence.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "status", content = "detail", rename_all = "snake_case")]
pub enum Outcome {
    Changed(String),
    Unchanged(String),
    Failed(String),
    Skipped(String),
}

impl Outcome {
    pub fn failed(&self) -> bool {
        match self {
            Self::Changed(_) | Self::Unchanged(_) => false,
            Self::Failed(_) | Self::Skipped(_) => true,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct History {
    pub current_visibility: Option<String>,
    pub checked_events: usize,
    pub encrypted_events: usize,
    pub decrypted_events: usize,
    pub inaccessible_events: usize,
    pub undecryptable_events: usize,
    pub redacted_events: usize,
    pub scan_complete: bool,
    pub failures: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RoomReport {
    pub room_id: String,
    pub name: Option<String>,
    pub source_membership: String,
    pub membership: Outcome,
    pub power: Outcome,
    pub tags: Outcome,
    pub keys: Outcome,
    pub history: History,
}

impl RoomReport {
    pub fn new(room_id: String, name: Option<String>, source_membership: String) -> Self {
        let pending = Outcome::Skipped("Not attempted".into());
        Self {
            room_id,
            name,
            source_membership,
            membership: pending.clone(),
            power: pending.clone(),
            tags: pending.clone(),
            keys: pending,
            history: History::default(),
        }
    }

    pub fn complete(&self) -> bool {
        !self.membership.failed()
            && !self.power.failed()
            && !self.tags.failed()
            && !self.keys.failed()
            && self.history.scan_complete
            && self.history.failures.is_empty()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Report {
    pub from: String,
    pub to: String,
    pub from_device: Option<String>,
    pub to_device: Option<String>,
    pub from_rooms: Vec<String>,
    pub to_rooms_before: Vec<String>,
    pub to_rooms_after: Vec<String>,
    pub preparation: Vec<Outcome>,
    pub direct: Outcome,
    pub rooms: Vec<RoomReport>,
    pub fatal: Option<String>,
}

impl Report {
    pub fn new(from: String, to: String) -> Self {
        Self {
            from,
            to,
            from_device: None,
            to_device: None,
            from_rooms: Vec::new(),
            to_rooms_before: Vec::new(),
            to_rooms_after: Vec::new(),
            preparation: Vec::new(),
            direct: Outcome::Skipped("Not attempted".into()),
            rooms: Vec::new(),
            fatal: None,
        }
    }

    pub fn complete(&self) -> bool {
        self.fatal.is_none()
            && !self.direct.failed()
            && !self.preparation.iter().any(Outcome::failed)
            && self.rooms.iter().all(RoomReport::complete)
    }
}

#[cfg(test)]
mod tests {
    use crate::report::{Outcome, Report, RoomReport};

    #[test]
    fn complete_requires_every_operation_and_full_history_audit() {
        let mut report = Report::new("from".into(), "to".into());
        assert!(!report.complete());
        report.direct = Outcome::Unchanged("Ready".into());
        let mut room = RoomReport::new("room".into(), None, "join".into());
        room.membership = Outcome::Unchanged("Joined".into());
        room.power = Outcome::Unchanged("Equal".into());
        room.tags = Outcome::Unchanged("Copied".into());
        room.keys = Outcome::Unchanged("Imported".into());
        report.rooms.push(room);
        assert!(!report.complete());
        report.rooms[0].history.scan_complete = true;
        assert!(report.complete());
        report.rooms[0].history.failures.push("One old message cannot decrypt".into());
        assert!(!report.complete());
        report.rooms.clear();
        report.fatal = Some("Login failed".into());
        assert!(!report.complete());
    }
}
