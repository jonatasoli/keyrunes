use chrono::{Duration, Utc};
use keyrunes::services::jwt_service::{Claims, JwtService};
use proptest::prelude::*;
use rstest::*;
use test_case::test_case;

// ============= JWT Service Tests =============

#[fixture]
fn jwt_service() -> JwtService {
    JwtService::new("test_secret_key_with_256_bits_minimum")
}

#[test]
fn test_jwt_creation_and_verification() {
    let service = jwt_service();
    
    let token = service.generate_token(
        123,
        "test@example.com",
        "testuser",
        vec!["users".to_string(), "admin".to_string()]
    ).unwrap();
    
    assert!(!token.is_empty());
    
    let claims = service.verify_token(&token).unwrap();
    assert_eq!(claims.sub, "123");
    assert_eq!(claims.email, "test@example.com");
    assert_eq!(claims.username, "testuser");
    assert_eq!(claims.groups, vec!["users", "admin"]);
    assert_eq!(claims.iss, "keyrunes");
}

#[test]
fn test_jwt_expiration() {
    let service = jwt_service();
    
    let token = service.generate_token(
        1,
        "test@example.com",
        "testuser",
        vec![]
    ).unwrap();
    
    let claims = service.verify_token(&token).unwrap();
    
    // Check that expiration is set to future (approximately 1 hour)
    let now = Utc::now().timestamp();
    assert!(claims.exp > now);
    assert!(claims.exp <= now + 3700); // Allow some margin
    assert!(claims.iat <= now);
}

#[test]
fn test_jwt_refresh() {
    let service = jwt_service();
    
    let original_token = service.generate_token(
        42,
        "refresh@example.com",
        "refreshuser",
        vec!["group1".to_string()]
    ).unwrap();
    
    let refreshed_token = service.refresh_token(&original_token).unwrap();
    
    assert_ne!(original_token, refreshed_token);
    
    let original_claims = service.verify_token(&original_token).unwrap();
    let refreshed_claims = service.verify_token(&refreshed_token).unwrap();
    
    assert_eq!(original_claims.sub, refreshed_claims.sub);
    assert_eq!(original_claims.email, refreshed_claims.email);
    assert_eq!(original_claims.username, refreshed_claims.username);
    assert_eq!(original_claims.groups, refreshed_claims.groups);
    assert!(refreshed_claims.exp > original_claims.exp);
}

#[test]
fn test_jwt_invalid_token() {
    let service = jwt_service();
    
    let result = service.verify_token("invalid.token.here");
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("Failed to decode JWT"));
}

#[test]
fn test_jwt_wrong_secret() {
    let service1 = JwtService::new("secret1");
    let service2 = JwtService::new("secret2");
    
    let token = service1.generate_token(1, "test@test.com", "test", vec![]).unwrap();
    
    let result = service2.verify_token(&token);
    assert!(result.is_err());
}

#[test]
fn test_jwt_extract_user_id() {
    let service = jwt_service();
    
    let token = service.generate_token(
        999,
        "test@example.com",
        "testuser",
        vec![]
    ).unwrap();
    
    let user_id = service.extract_user_id(&token).unwrap();
    assert_eq!(user_id, 999);
}

#[test]
fn test_jwt_extract_user_id_invalid_token() {
    let service = jwt_service();
    
    let result = service.extract_user_id("invalid.token");
    assert!(result.is_err());
}

#[rstest]
#[case(1, "user1@test.com", "user1", vec![])]
#[case(999999, "admin@company.org", "superadmin", vec!["admin".to_string(), "superuser".to_string()])]
#[case(0, "guest@temp.net", "guest_user", vec!["guest".to_string()])]
fn test_jwt_various_users(
    #[case] user_id: i64,
    #[case] email: &str,
    #[case] username: &str,
    #[case] groups: Vec<String>,
) {
    let service = jwt_service();
    
    let token = service.generate_token(user_id, email, username, groups.clone()).unwrap();
    let claims = service.verify_token(&token).unwrap();
    
    assert_eq!(claims.sub, user_id.to_string());
    assert_eq!(claims.email, email);
    assert_eq!(claims.username, username);
    assert_eq!(claims.groups, groups);
}

#[test_case("", "email", "user", vec![] => false ; "empty secret")]
#[test_case("valid_secret", "", "user", vec![] => true ; "empty email")]
#[test_case("valid_secret", "email", "", vec![] => true ; "empty username")]
fn test_jwt_edge_cases(
    secret: &str,
    email: &str,
    username: &str,
    groups: Vec<String>
) -> bool {
    if secret.is_empty() {
        // JwtService creation should work even with empty secret (though not secure)
        let service = JwtService::new(secret);
        service.generate_token(1, email, username, groups).is_ok()
    } else {
        let service = JwtService::new(secret);
        service.generate_token(1, email, username, groups).is_ok()
    }
}

proptest! {
    #[test]
    fn test_jwt_with_random_data(
        user_id in 1i64..1000000,
        email in "[a-z]{1,10}@[a-z]{1,10}\\.[a-z]{2,3}",
        username in "[a-zA-Z0-9_]{1,20}",
        groups_count in 0usize..10
    ) {
        let service = JwtService::new("test_secret");
        let groups: Vec<String> = (0..groups_count)
            .map(|i| format!("group_{}", i))
            .collect();
        
        let token = service.generate_token(user_id, &email, &username, groups.clone()).unwrap();
        let claims = service.verify_token(&token).unwrap();
        
        prop_assert_eq!(claims.sub, user_id.to_string());
        prop_assert_eq!(claims.email, email);
        prop_assert_eq!(claims.username, username);
        prop_assert_eq!(claims.groups.len(), groups_count);
    }
    
    #[test]
    fn test_jwt_token_length(
        user_id in 1i64..1000000,
        username_len in 1usize..50
    ) {
        let service = JwtService::new("test_secret");
        let username = "a".repeat(username_len);
        
        let token = service.generate_token(
            user_id,
            "test@test.com",
            &username,
            vec![]
        ).unwrap();
        
        // JWT tokens should have consistent structure
        let parts: Vec<&str> = token.split('.').collect();
        prop_assert_eq!(parts.len(), 3); // header.payload.signature
        prop_assert!(!parts[0].is_empty());
        prop_assert!(!parts[1].is_empty());
        prop_assert!(!parts[2].is_empty());
    }
}

// ============= Health Check Tests =============

#[cfg(test)]
mod health_tests {
    use axum::{
        body::Body,
        extract::Extension,
        http::{Request, StatusCode},
    };
    use keyrunes::api::health::{health_check, liveness_check, readiness_check, init_health_check};
    use sqlx::PgPool;
    use tower::ServiceExt;
    
    #[tokio::test]
    async fn test_liveness_check() {
        let response = liveness_check().await.into_response();
        let (parts, body) = response.into_parts();
        
        assert_eq!(parts.status, StatusCode::OK);
        
        let body_bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
        let body_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        
        assert_eq!(body_json["status"], "alive");
        assert!(body_json["timestamp"].is_string());
        assert!(body_json["version"].is_string());
    }
    
    #[tokio::test]
    async fn test_health_check_structure() {
        use keyrunes::api::health::{test_jwt_service, test_password_hashing};
        
        // Test individual components
        assert!(test_jwt_service().is_ok());
        assert!(test_password_hashing().is_ok());
    }
    
    #[tokio::test]
    async fn test_health_check_initialization() {
        init_health_check();
        // Should not panic and should initialize the start time
        
        // Run it again to ensure idempotency
        init_health_check();
    }
    
    #[test]
    fn test_password_hashing_service() {
        use argon2::{Argon2, password_hash::{PasswordHasher, PasswordVerifier, SaltString}};
        use password_hash::PasswordHash;
        use rand::thread_rng;
        
        let password = "test_password_123";
        let salt = SaltString::generate(thread_rng());
        let argon2 = Argon2::default();
        
        let hash = argon2.hash_password(password.as_bytes(), &salt).unwrap();
        let hash_string = hash.to_string();
        
        let parsed_hash = PasswordHash::new(&hash_string).unwrap();
        assert!(argon2.verify_password(password.as_bytes(), &parsed_hash).is_ok());
        
        // Wrong password should fail
        assert!(argon2.verify_password(b"wrong_password", &parsed_hash).is_err());
    }
}

// ============= Claims Tests =============

#[test]
fn test_claims_serialization() {
    let claims = Claims {
        sub: "123".to_string(),
        email: "test@example.com".to_string(),
        username: "testuser".to_string(),
        groups: vec!["admin".to_string(), "users".to_string()],
        exp: 1234567890,
        iat: 1234567800,
        iss: "keyrunes".to_string(),
    };
    
    let json = serde_json::to_string(&claims).unwrap();
    let deserialized: Claims = serde_json::from_str(&json).unwrap();
    
    assert_eq!(claims.sub, deserialized.sub);
    assert_eq!(claims.email, deserialized.email);
    assert_eq!(claims.username, deserialized.username);
    assert_eq!(claims.groups, deserialized.groups);
    assert_eq!(claims.exp, deserialized.exp);
    assert_eq!(claims.iat, deserialized.iat);
    assert_eq!(claims.iss, deserialized.iss);
}

// ============= Integration Tests =============

#[tokio::test]
async fn test_jwt_lifecycle() {
    let service = JwtService::new("integration_test_secret");
    
    // Create multiple tokens for the same user
    let tokens: Vec<String> = (0..5).map(|i| {
        service.generate_token(
            100,
            "user@test.com",
            "testuser",
            vec![format!("group_{}", i)]
        ).unwrap()
    }).collect();
    
    // All tokens should be different
    for i in 0..tokens.len() {
        for j in (i+1)..tokens.len() {
            assert_ne!(tokens[i], tokens[j]);
        }
    }
    
    // All tokens should be valid
    for token in &tokens {
        assert!(service.verify_token(token).is_ok());
    }
    
    // Extract user ID from all tokens
    for token in &tokens {
        assert_eq!(service.extract_user_id(token).unwrap(), 100);
    }
    
    // Refresh all tokens
    let refreshed: Vec<String> = tokens.iter()
        .map(|t| service.refresh_token(t).unwrap())
        .collect();
    
    // All refreshed tokens should be different from originals
    for i in 0..tokens.len() {
        assert_ne!(tokens[i], refreshed[i]);
    }
}

#[test]
fn test_jwt_with_special_characters() {
    let service = jwt_service();
    
    let special_cases = vec![
        ("user@example.com", "user_name", vec!["group-1".to_string()]),
        ("admin+test@company.org", "admin.user", vec!["group/admin".to_string()]),
        ("test\\user@test.com", "test:user", vec!["group@test".to_string()]),
    ];
    
    for (email, username, groups) in special_cases {
        let token = service.generate_token(1, email, username, groups.clone()).unwrap();
        let claims = service.verify_token(&token).unwrap();
        
        assert_eq!(claims.email, email);
        assert_eq!(claims.username, username);
        assert_eq!(claims.groups, groups);
    }
}

#[test]
fn test_jwt_with_very_long_data() {
    let service = jwt_service();
    
    let long_email = format!("{}@example.com", "a".repeat(100));
    let long_username = "u".repeat(100);
    let many_groups: Vec<String> = (0..100).map(|i| format!("group_{}", i)).collect();
    
    let token = service.generate_token(
        999999999,
        &long_email,
        &long_username,
        many_groups.clone()
    ).unwrap();
    
    let claims = service.verify_token(&token).unwrap();
    assert_eq!(claims.email, long_email);
    assert_eq!(claims.username, long_username);
    assert_eq!(claims.groups.len(), 100);
}

#[test]
fn test_jwt_boundary_values() {
    let service = jwt_service();
    
    // Test with minimum values
    let token = service.generate_token(0, "", "", vec![]).unwrap();
    let claims = service.verify_token(&token).unwrap();
    assert_eq!(claims.sub, "0");
    assert_eq!(claims.email, "");
    assert_eq!(claims.username, "");
    assert!(claims.groups.is_empty());
    
    // Test with maximum reasonable values
    let token = service.generate_token(
        i64::MAX,
        "max@example.com",
        "maxuser",
        vec!["group".to_string(); 1000]
    ).unwrap();
    let claims = service.verify_token(&token).unwrap();
    assert_eq!(claims.sub, i64::MAX.to_string());
    assert_eq!(claims.groups.len(), 1000);
}

// ============= Error Handling Tests =============

#[test]
fn test_jwt_malformed_tokens() {
    let service = jwt_service();
    
    let malformed_tokens = vec![
        "",
        "not.a.token",
        "only.two",
        "way.too.many.parts.here",
        "aGVsbG8=.d29ybGQ=.Zm9v", // base64 but not JWT
        "eyJhbGciOiJIUzI1NiJ9.invalid_payload.signature",
    ];
    
    for token in malformed_tokens {
        assert!(service.verify_token(token).is_err());
        assert!(service.extract_user_id(token).is_err());
        assert!(service.refresh_token(token).is_err());
    }
}

#[test]
fn test_jwt_expired_token_simulation() {
    // We can't easily create an expired token without manipulating time,
    // but we can test that the verification handles the exp claim
    let service = jwt_service();
    
    let token = service.generate_token(1, "test@test.com", "test", vec![]).unwrap();
    let claims = service.verify_token(&token).unwrap();
    
    // The exp should be in the future
    let now = Utc::now().timestamp();
    assert!(claims.exp > now);
    
    // The iat should be in the past or present
    assert!(claims.iat <= now);
}
