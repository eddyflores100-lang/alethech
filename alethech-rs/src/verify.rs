//! Verification engine — check signatures, DAG integrity, identity binding.

use crate::objects::MemoryCommit;

/// Verify a single commit's signature and commit_id.
pub fn verify_commit(commit: &MemoryCommit, public_key: &[u8; 32]) -> bool {
    // Verify signature
    if !commit.verify(public_key) {
        return false;
    }

    // Verify commit_id matches content
    let mut check = commit.clone();
    let original_id = check.commit_id.clone();
    check.compute_commit_id();

    check.commit_id == original_id
}

/// Verify that commit_id is in the ancestry of cutoff_head.
/// Returns true if commit_id == cutoff_head or reachable by following parents.
pub fn ancestry_check(
    commit_id: &str,
    cutoff_head: &str,
    commits: &std::collections::HashMap<String, MemoryCommit>,
) -> bool {
    if commit_id == cutoff_head {
        return true;
    }

    let mut visited = std::collections::HashSet::new();
    let mut queue = vec![cutoff_head.to_string()];

    while !queue.is_empty() {
        let current = queue.remove(0);
        if visited.contains(&current) {
            continue;
        }
        visited.insert(current.clone());

        if current == commit_id {
            return true;
        }

        if let Some(commit) = commits.get(&current) {
            for parent in &commit.parents {
                if !visited.contains(parent) {
                    queue.push(parent.clone());
                }
            }
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KeyPair;
    use crate::objects::Identity;
    use serde_json::json;
    use std::collections::HashMap;

    #[test]
    fn test_verify_valid_commit() {
        let kp = KeyPair::generate();
        let pk = kp.public_key_bytes();
        let ident = Identity::from_public_key(&pk, "key-001");

        let mut commit = MemoryCommit::new(
            &ident.agent_id,
            "key-001",
            vec![],
            json!({"test": true}),
        );
        commit.sign(&kp);

        assert!(verify_commit(&commit, &pk));
    }

    #[test]
    fn test_verify_tampered_commit() {
        let kp = KeyPair::generate();
        let pk = kp.public_key_bytes();
        let ident = Identity::from_public_key(&pk, "key-001");

        let mut commit = MemoryCommit::new(
            &ident.agent_id,
            "key-001",
            vec![],
            json!({"test": true}),
        );
        commit.sign(&kp);

        // Tamper with content
        commit.content = json!({"test": false});
        assert!(!verify_commit(&commit, &pk));
    }

    #[test]
    fn test_ancestry_check_direct() {
        let result = ancestry_check("c1", "c1", &HashMap::new());
        assert!(result);
    }

    #[test]
    fn test_ancestry_check_parent() {
        let kp = KeyPair::generate();
        let pk = kp.public_key_bytes();
        let ident = Identity::from_public_key(&pk, "key-001");

        let mut genesis = MemoryCommit::new(
            &ident.agent_id,
            "key-001",
            vec![],
            json!({"v": 0}),
        );
        genesis.sign(&kp);

        let mut child = MemoryCommit::new(
            &ident.agent_id,
            "key-001",
            vec![genesis.commit_id.clone()],
            json!({"v": 1}),
        );
        child.sign(&kp);

        let mut commits = HashMap::new();
        let genesis_id = genesis.commit_id.clone();
        commits.insert(genesis_id.clone(), genesis);
        let child_id = child.commit_id.clone();
        commits.insert(child_id.clone(), child);

        // Genesis should be in ancestry of child
        assert!(ancestry_check(
            &genesis_id,
            &child_id,
            &commits
        ));
    }

    #[test]
    fn test_ancestry_check_unreachable() {
        let kp = KeyPair::generate();
        let pk = kp.public_key_bytes();
        let ident = Identity::from_public_key(&pk, "key-001");

        let mut genesis = MemoryCommit::new(
            &ident.agent_id,
            "key-001",
            vec![],
            json!({"v": 0}),
        );
        genesis.sign(&kp);

        let mut orphan = MemoryCommit::new(
            &ident.agent_id,
            "key-001",
            vec!["sha256:nonexistent".to_string()],
            json!({"v": 2}),
        );
        orphan.sign(&kp);

        let mut commits = HashMap::new();
        let genesis_id = genesis.commit_id.clone();
        commits.insert(genesis_id.clone(), genesis);
        let orphan_id = orphan.commit_id.clone();
        commits.insert(orphan_id.clone(), orphan);

        // Orphan should NOT be in ancestry of genesis
        assert!(!ancestry_check(
            &orphan_id,
            &genesis_id,
            &commits
        ));
    }
}
