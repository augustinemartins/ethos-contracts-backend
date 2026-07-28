#[cfg(test)]
mod tests {
    use crate::credential_anchoring::*;
    use soroban_sdk::{Bytes, Env};

    #[test]
    fn test_create_and_verify_anchor() {
        let env = Env::default();

        let credential_id = 42u64;
        let external_id = Bytes::from_slice(&env, b"external-id-123");
        let system = Bytes::from_slice(&env, b"kyc-v1");

        // Create anchor
        let success =
            create_credential_anchor(&env, credential_id, external_id.clone(), system.clone());
        assert!(success, "Anchor creation should succeed");

        // Verify anchor
        let result = verify_external_anchor(&env, &external_id, &system);
        assert_eq!(
            result,
            Some(credential_id),
            "Should retrieve correct credential ID"
        );

        // Check existence
        let exists = anchor_exists(&env, &external_id, &system);
        assert!(exists, "Anchor should exist");
    }

    #[test]
    fn test_duplicate_anchor_rejected() {
        let env = Env::default();

        let credential_id = 1u64;
        let external_id = Bytes::from_slice(&env, b"external-id-123");
        let system = Bytes::from_slice(&env, b"kyc-v1");

        // Create anchor
        let success1 =
            create_credential_anchor(&env, credential_id, external_id.clone(), system.clone());
        assert!(success1, "First anchor creation should succeed");

        // Try to create duplicate
        let success2 =
            create_credential_anchor(&env, credential_id, external_id.clone(), system.clone());
        assert!(!success2, "Duplicate anchor should be rejected");
    }

    #[test]
    fn test_remove_anchor() {
        let env = Env::default();

        let credential_id = 42u64;
        let external_id = Bytes::from_slice(&env, b"external-id-123");
        let system = Bytes::from_slice(&env, b"kyc-v1");

        // Create anchor
        let _ = create_credential_anchor(&env, credential_id, external_id.clone(), system.clone());
        assert!(
            anchor_exists(&env, &external_id, &system),
            "Anchor should exist"
        );

        // Remove anchor
        let success = remove_credential_anchor(&env, credential_id, &external_id, &system);
        assert!(success, "Anchor removal should succeed");

        // Verify it's gone
        let result = verify_external_anchor(&env, &external_id, &system);
        assert_eq!(result, None, "Anchor should be gone");
    }

    #[test]
    fn test_multiple_anchors_per_credential() {
        let env = Env::default();

        let credential_id = 42u64;
        let external_id_1 = Bytes::from_slice(&env, b"external-id-1");
        let external_id_2 = Bytes::from_slice(&env, b"external-id-2");
        let system_1 = Bytes::from_slice(&env, b"kyc-v1");
        let system_2 = Bytes::from_slice(&env, b"gov-id");

        // Create multiple anchors
        let success1 =
            create_credential_anchor(&env, credential_id, external_id_1.clone(), system_1.clone());
        let success2 =
            create_credential_anchor(&env, credential_id, external_id_2.clone(), system_2.clone());

        assert!(success1, "First anchor should succeed");
        assert!(success2, "Second anchor should succeed");

        // Get all anchors
        let anchors = get_credential_anchors(&env, credential_id);
        assert_eq!(anchors.len(), 2, "Should have 2 anchors");
    }

    #[test]
    fn test_anchor_counter() {
        let env = Env::default();

        let initial_count = get_anchor_count(&env);
        assert_eq!(initial_count, 0, "Initial count should be 0");

        // Create an anchor
        let external_id = Bytes::from_slice(&env, b"test-id");
        let system = Bytes::from_slice(&env, b"test-sys");
        let _ = create_credential_anchor(&env, 1u64, external_id, system);

        let count_after = get_anchor_count(&env);
        assert_eq!(count_after, 1, "Count should increment");
    }
}
