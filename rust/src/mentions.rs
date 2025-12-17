//! Mentions parsing (Phase 8)
//!
//! Client-side only, no protocol changes.
//! - Extracts `@nickname` tokens from plaintext.
//! - Matches against known friends (by `nickname`).

use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct FriendInfo {
    pub user_id: String,
    pub nickname: String,
}

#[derive(Debug, Serialize)]
pub struct Mention {
    pub user_id: String,
    pub nickname: String,
}

/// Extract mentions from text given known friends.
pub fn extract_mentions(text: &str, friends: &[FriendInfo]) -> Vec<Mention> {
    if friends.is_empty() {
        return Vec::new();
    }

    // Build quick lookup by nickname (case-sensitive).
    let mut by_nick = std::collections::HashMap::new();
    for f in friends {
        by_nick.insert(f.nickname.clone(), f.user_id.clone());
    }

    let mut mentions = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for token in text.split_whitespace() {
        if let Some(stripped) = token.strip_prefix('@') {
            // Remove trailing punctuation from nickname like @alice, or @bob!.
            let nick: String = stripped
                .chars()
                .take_while(|ch| ch.is_alphanumeric() || *ch == '_' || *ch == '-')
                .collect();
            if nick.is_empty() {
                continue;
            }
            if let Some(user_id) = by_nick.get(&nick) {
                if seen.insert(user_id.clone()) {
                    mentions.push(Mention {
                        user_id: user_id.clone(),
                        nickname: nick.clone(),
                    });
                }
            }
        }
    }

    mentions
}



