//! Pure convergence policies retain unrelated JSON fields and destination-only metadata.

use anyhow::{Result, ensure};
use serde_json::{Value, json};

/// Merge m.direct by peer, preserving destination-only rooms and avoiding duplicates.
pub fn merge_direct(destination: &Value, source: &Value) -> Result<Value> {
    let mut result = destination
        .as_object()
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("m.direct must be an object"))?;
    let source =
        source.as_object().ok_or_else(|| anyhow::anyhow!("Source m.direct must be an object"))?;
    for (peer, rooms) in source {
        let rooms =
            rooms.as_array().ok_or_else(|| anyhow::anyhow!("m.direct[{peer}] must be an array"))?;
        let entry = result.entry(peer).or_insert_with(|| json!([]));
        let entry = entry
            .as_array_mut()
            .ok_or_else(|| anyhow::anyhow!("Destination m.direct[{peer}] must be an array"))?;
        for room in rooms {
            ensure!(room.as_str().is_some(), "m.direct room IDs must be strings");
            if !entry.contains(room) {
                entry.push(room.clone());
            }
        }
    }
    Ok(Value::Object(result))
}

/// Compute a power-level increase; return None when the target already has sufficient power.
pub fn increase_power(content: &Value, from: &str, to: &str) -> Result<Option<Value>> {
    let mut content = content.clone();
    ensure!(content.is_object(), "m.room.power_levels must be an object");
    let default = integer(&content, "users_default", 0)?;
    let users = content.get("users").cloned().unwrap_or_else(|| json!({}));
    ensure!(users.is_object(), "m.room.power_levels.users must be an object");
    let from_level = integer(&users, from, default)?;
    let to_level = integer(&users, to, default)?;
    if to_level >= from_level {
        return Ok(None);
    }
    let mut users = users;
    users[to] = json!(from_level);
    content["users"] = users;
    Ok(Some(content))
}

fn integer(content: &Value, key: &str, default: i64) -> Result<i64> {
    match content.get(key) {
        None => Ok(default),
        Some(value) => {
            value.as_i64().ok_or_else(|| anyhow::anyhow!("Power level {key} must be an integer"))
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::policy::{increase_power, merge_direct};
    use serde_json::json;

    #[test]
    fn power_only_increases_and_preserves_unknown_fields() {
        let original = json!({"users": {"from": 50, "to": 0, "other": 100}, "future": [1]});
        let result = increase_power(&original, "from", "to").unwrap().unwrap();
        assert_eq!(result["users"]["to"], 50);
        assert_eq!(result["users"]["other"], 100);
        assert_eq!(result["future"], json!([1]));
        assert!(increase_power(&result, "from", "to").unwrap().is_none());
        assert!(increase_power(&result, "to", "other").unwrap().is_none());
    }

    #[test]
    fn power_defaults_and_negative_levels_are_respected() {
        let result =
            increase_power(&json!({"users_default": -10, "users": {"from": 0}}), "from", "to")
                .unwrap()
                .unwrap();
        assert_eq!(result["users"]["to"], 0);
        assert!(increase_power(&json!({}), "from", "to").unwrap().is_none());
        assert!(increase_power(&json!({"users": []}), "from", "to").is_err());
        assert!(increase_power(&json!({"users_default": "100"}), "from", "to").is_err());
    }

    #[test]
    fn direct_merge_is_lossless_and_converges() {
        let target = json!({"@peer:s": ["!old:s"], "@other:s": ["!other:s"]});
        let source = json!({"@peer:s": ["!new:s", "!new:s"]});
        let merged = merge_direct(&target, &source).unwrap();
        assert_eq!(merged, json!({"@peer:s": ["!old:s", "!new:s"], "@other:s": ["!other:s"]}));
        assert_eq!(merge_direct(&merged, &source).unwrap(), merged);
        assert!(merge_direct(&json!({}), &json!({"x": [42]})).is_err());
        assert!(merge_direct(&json!({"x": false}), &json!({"x": []})).is_err());
    }
}
