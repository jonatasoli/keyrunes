use anyhow::Result;
use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use keyrunes::repository::{
    Group, GroupRepository, NewGroup, NewPasswordResetToken, NewUser, PasswordResetRepository,
    PasswordResetToken, Policy, User, UserRepository,
};
use keyrunes::services::jwt_service::JwtService;
use keyrunes::services::user_service::{
    ChangePasswordRequest, ForgotPasswordRequest, RegisterRequest, ResetPasswordRequest,
    UserService,
};
use proptest::prelude::*;
use rstest::*;
use std::sync::{Arc, Mutex};
use test_case::test_case;
use uuid::Uuid;

// ============= Mock Implementations =============

#[derive(Clone)]
struct MockUserRepository {
    users: Arc<Mutex<Vec<User>>>,
    groups: Arc<Mutex<Vec<(i64, i64)>>>, // (user_id, group_id)
    should_fail: Arc<Mutex<bool>>,
}

impl MockUserRepository {
    fn new() -> Self {
        Self {
            users: Arc::new(Mutex::new(Vec::new())),
            groups: Arc::new(Mutex::new(Vec::new())),
            should_fail: Arc::new(Mutex::new(false)),
        }
    }

    fn set_should_fail(&self, fail: bool) {
        *self.should_fail.lock().unwrap() = fail;
    }

    fn add_test_user(&self, email: &str, username: &str, password_hash: &str) -> User {
        let user = User {
            user_id: self.users.lock().unwrap().len() as i64 + 1,
            external_id: Uuid::new_v4(),
            email: email.to_string(),
            username: username.to_string(),
            password_hash: password_hash.to_string(),
            first_login: false,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        self.users.lock().unwrap().push(user.clone());
        user
    }
}

#[async_trait]
impl UserRepository for MockUserRepository {
    async fn find_by_email(&self, email: &str) -> Result<Option<User>> {
        if *self.should_fail.lock().unwrap() {
            return Err(anyhow::anyhow!("Database error"));
        }
        Ok(self.users.lock().unwrap().iter().find(|u| u.email == email).cloned())
    }

    async fn find_by_username(&self, username: &str) -> Result<Option<User>> {
        if *self.should_fail.lock().unwrap() {
            return Err(anyhow::anyhow!("Database error"));
        }
        Ok(self.users.lock().unwrap().iter().find(|u| u.username == username).cloned())
    }

    async fn find_by_id(&self, user_id: i64) -> Result<Option<User>> {
        if *self.should_fail.lock().unwrap() {
            return Err(anyhow::anyhow!("Database error"));
        }
        Ok(self.users.lock().unwrap().iter().find(|u| u.user_id == user_id).cloned())
    }

    async fn insert_user(&self, new_user: NewUser) -> Result<User> {
        if *self.should_fail.lock().unwrap() {
            return Err(anyhow::anyhow!("Database error"));
        }
        let user = User {
            user_id: self.users.lock().unwrap().len() as i64 + 1,
            external_id: new_user.external_id,
            email: new_user.email,
            username: new_user.username,
            password_hash: new_user.password_hash,
            first_login: new_user.first_login,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        self.users.lock().unwrap().push(user.clone());
        Ok(user)
    }

    async fn update_user_password(&self, user_id: i64, new_password_hash: &str) -> Result<()> {
        if *self.should_fail.lock().unwrap() {
            return Err(anyhow::anyhow!("Database error"));
        }
        let mut users = self.users.lock().unwrap();
        if let Some(user) = users.iter_mut().find(|u| u.user_id == user_id) {
            user.password_hash = new_password_hash.to_string();
            user.updated_at = Utc::now();
        }
        Ok(())
    }

    async fn set_first_login(&self, user_id: i64, first_login: bool) -> Result<()> {
        if *self.should_fail.lock().unwrap() {
            return Err(anyhow::anyhow!("Database error"));
        }
        let mut users = self.users.lock().unwrap();
        if let Some(user) = users.iter_mut().find(|u| u.user_id == user_id) {
            user.first_login = first_login;
            user.updated_at = Utc::now();
        }
        Ok(())
    }

    async fn get_user_groups(&self, user_id: i64) -> Result<Vec<Group>> {
        if *self.should_fail.lock().unwrap() {
            return Err(anyhow::anyhow!("Database error"));
        }
        let groups = self.groups.lock().unwrap();
        let user_groups: Vec<Group> = groups
            .iter()
            .filter(|(uid, _)| *uid == user_id)
            .map(|(_, gid)| Group {
                group_id: *gid,
                external_id: Uuid::new_v4(),
                name: format!("group_{}", gid),
                description: None,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            })
            .collect();
        Ok(user_groups)
    }

    async fn get_user_policies(&self, _user_id: i64) -> Result<Vec<Policy>> {
        Ok(Vec::new())
    }

    async fn get_user_all_policies(&self, _user_id: i64) -> Result<Vec<Policy>> {
        Ok(Vec::new())
    }
}

#[derive(Clone)]
struct MockGroupRepository {
    groups: Arc<Mutex<Vec<Group>>>,
}

impl MockGroupRepository {
    fn new() -> Self {
        let mut groups = Vec::new();
        groups.push(Group {
            group_id: 1,
            external_id: Uuid::new_v4(),
            name: "users".to_string(),
            description: Some("Default users group".to_string()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        });
        groups.push(Group {
            group_id: 2,
            external_id: Uuid::new_v4(),
            name: "admin".to_string(),
            description: Some("Admin group".to_string()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        });
        
        Self {
            groups: Arc::new(Mutex::new(groups)),
        }
    }
}

#[async_trait]
impl GroupRepository for MockGroupRepository {
    async fn find_by_name(&self, name: &str) -> Result<Option<Group>> {
        Ok(self.groups.lock().unwrap().iter().find(|g| g.name == name).cloned())
    }

    async fn find_by_id(&self, group_id: i64) -> Result<Option<Group>> {
        Ok(self.groups.lock().unwrap().iter().find(|g| g.group_id == group_id).cloned())
    }

    async fn insert_group(&self, new_group: NewGroup) -> Result<Group> {
        let group = Group {
            group_id: self.groups.lock().unwrap().len() as i64 + 1,
            external_id: new_group.external_id,
            name: new_group.name,
            description: new_group.description,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        self.groups.lock().unwrap().push(group.clone());
        Ok(group)
    }

    async fn list_groups(&self) -> Result<Vec<Group>> {
        Ok(self.groups.lock().unwrap().clone())
    }

    async fn assign_user_to_group(
        &self,
        _user_id: i64,
        _group_id: i64,
        _assigned_by: Option<i64>,
    ) -> Result<()> {
        Ok(())
    }

    async fn remove_user_from_group(&self, _user_id: i64, _group_id: i64) -> Result<()> {
        Ok(())
    }

    async fn get_group_policies(&self, _group_id: i64) -> Result<Vec<Policy>> {
        Ok(Vec::new())
    }
}

#[derive(Clone)]
struct MockPasswordResetRepository {
    tokens: Arc<Mutex<Vec<PasswordResetToken>>>,
}

impl MockPasswordResetRepository {
    fn new() -> Self {
        Self {
            tokens: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

#[async_trait]
impl PasswordResetRepository for MockPasswordResetRepository {
    async fn create_reset_token(&self, token: NewPasswordResetToken) -> Result<PasswordResetToken> {
        let reset_token = PasswordResetToken {
            token_id: self.tokens.lock().unwrap().len() as i64 + 1,
            user_id: token.user_id,
            token: token.token,
            expires_at: token.expires_at,
            used_at: None,
            created_at: Utc::now(),
        };
        self.tokens.lock().unwrap().push(reset_token.clone());
        Ok(reset_token)
    }

    async fn find_valid_token(&self, token: &str) -> Result<Option<PasswordResetToken>> {
        Ok(self.tokens
            .lock()
            .unwrap()
            .iter()
            .find(|t| t.token == token && t.expires_at > Utc::now() && t.used_at.is_none())
            .cloned())
    }

    async fn mark_token_used(&self, token_id: i64) -> Result<()> {
        let mut tokens = self.tokens.lock().unwrap();
        if let Some(token) = tokens.iter_mut().find(|t| t.token_id == token_id) {
            token.used_at = Some(Utc::now());
        }
        Ok(())
    }

    async fn cleanup_expired_tokens(&self) -> Result<()> {
        let mut tokens = self.tokens.lock().unwrap();
        tokens.retain(|t| t.expires_at > Utc::now());
        Ok(())
    }
}

// ============= Fixtures =============

#[fixture]
fn test_service() -> UserService<MockUserRepository, MockGroupRepository, MockPasswordResetRepository> {
    let user_repo = Arc::new(MockUserRepository::new());
    let group_repo = Arc::new(MockGroupRepository::new());
    let password_reset_repo = Arc::new(MockPasswordResetRepository::new());
    let jwt_service = Arc::new(JwtService::new("test_secret_key"));
    
    UserService::new(user_repo, group_repo, password_reset_repo, jwt_service)
}

#[fixture]
fn valid_register_request() -> RegisterRequest {
    RegisterRequest {
        email: "test@example.com".to_string(),
        username: "testuser".to_string(),
        password: "SecurePass123!".to_string(),
    }
}

// ============= Standard Tests =============

#[tokio::test]
async fn test_register_success() {
    let service = test_service();
    let req = valid_register_request();
    
    let result = service.register(req).await;
    assert!(result.is_ok());
    
    let auth = result.unwrap();
    assert_eq!(auth.user.email, "test@example.com");
    assert_eq!(auth.user.username, "testuser");
    assert!(!auth.token.is_empty());
    assert!(!auth.requires_password_change);
}

#[tokio::test]
async fn test_register_invalid_email() {
    let service = test_service();
    let req = RegisterRequest {
        email: "invalid-email".to_string(),
        username: "testuser".to_string(),
        password: "SecurePass123!".to_string(),
    };
    
    let result = service.register(req).await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().to_string(), "invalid email");
}

#[tokio::test]
async fn test_register_short_password() {
    let service = test_service();
    let req = RegisterRequest {
        email: "test@example.com".to_string(),
        username: "testuser".to_string(),
        password: "short".to_string(),
    };
    
    let result = service.register(req).await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().to_string(), "password too short");
}

#[tokio::test]
async fn test_register_duplicate_email() {
    let service = test_service();
    let req = valid_register_request();
    
    // First registration should succeed
    assert!(service.register(req.clone()).await.is_ok());
    
    // Second registration with same email should fail
    let result = service.register(req).await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().to_string(), "email already registered");
}

#[tokio::test]
async fn test_register_duplicate_username() {
    let service = test_service();
    let req1 = RegisterRequest {
        email: "test1@example.com".to_string(),
        username: "testuser".to_string(),
        password: "SecurePass123!".to_string(),
    };
    let req2 = RegisterRequest {
        email: "test2@example.com".to_string(),
        username: "testuser".to_string(),
        password: "SecurePass123!".to_string(),
    };
    
    // First registration should succeed
    assert!(service.register(req1).await.is_ok());
    
    // Second registration with same username should fail
    let result = service.register(req2).await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().to_string(), "username taken");
}

#[tokio::test]
async fn test_login_with_email() {
    let service = test_service();
    let req = valid_register_request();
    
    // Register user first
    service.register(req.clone()).await.unwrap();
    
    // Login with email
    let result = service.login(req.email, req.password).await;
    assert!(result.is_ok());
    
    let auth = result.unwrap();
    assert_eq!(auth.user.username, "testuser");
    assert!(!auth.token.is_empty());
}

#[tokio::test]
async fn test_login_with_username() {
    let service = test_service();
    let req = valid_register_request();
    
    // Register user first
    service.register(req.clone()).await.unwrap();
    
    // Login with username
    let result = service.login(req.username, req.password).await;
    assert!(result.is_ok());
    
    let auth = result.unwrap();
    assert_eq!(auth.user.email, "test@example.com");
}

#[tokio::test]
async fn test_login_invalid_credentials() {
    let service = test_service();
    let req = valid_register_request();
    
    // Register user first
    service.register(req.clone()).await.unwrap();
    
    // Try login with wrong password
    let result = service.login(req.email, "WrongPassword".to_string()).await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().to_string(), "invalid credentials");
}

#[tokio::test]
async fn test_login_nonexistent_user() {
    let service = test_service();
    
    let result = service.login("nonexistent@example.com".to_string(), "password".to_string()).await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().to_string(), "invalid credentials");
}

#[tokio::test]
async fn test_change_password_success() {
    let service = test_service();
    let req = valid_register_request();
    
    // Register user
    let auth = service.register(req.clone()).await.unwrap();
    
    // Change password
    let change_req = ChangePasswordRequest {
        current_password: req.password,
        new_password: "NewSecurePass456!".to_string(),
    };
    
    let result = service.change_password(auth.user.user_id, change_req).await;
    assert!(result.is_ok());
    
    // Verify can login with new password
    let login_result = service.login(
        "test@example.com".to_string(),
        "NewSecurePass456!".to_string()
    ).await;
    assert!(login_result.is_ok());
}

#[tokio::test]
async fn test_change_password_wrong_current() {
    let service = test_service();
    let req = valid_register_request();
    
    // Register user
    let auth = service.register(req).await.unwrap();
    
    // Try to change password with wrong current password
    let change_req = ChangePasswordRequest {
        current_password: "WrongPassword".to_string(),
        new_password: "NewSecurePass456!".to_string(),
    };
    
    let result = service.change_password(auth.user.user_id, change_req).await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().to_string(), "current password is incorrect");
}

#[tokio::test]
async fn test_forgot_password_success() {
    let service = test_service();
    let req = valid_register_request();
    
    // Register user
    service.register(req.clone()).await.unwrap();
    
    // Request password reset
    let forgot_req = ForgotPasswordRequest {
        email: req.email,
    };
    
    let result = service.forgot_password(forgot_req).await;
    assert!(result.is_ok());
    
    let token = result.unwrap();
    assert!(!token.is_empty());
}

#[tokio::test]
async fn test_reset_password_success() {
    let service = test_service();
    let req = valid_register_request();
    
    // Register user
    service.register(req.clone()).await.unwrap();
    
    // Request password reset
    let forgot_req = ForgotPasswordRequest {
        email: req.email.clone(),
    };
    let token = service.forgot_password(forgot_req).await.unwrap();
    
    // Reset password
    let reset_req = ResetPasswordRequest {
        token,
        new_password: "NewResetPass789!".to_string(),
    };
    
    let result = service.reset_password(reset_req).await;
    assert!(result.is_ok());
    
    // Verify can login with new password
    let login_result = service.login(req.email, "NewResetPass789!".to_string()).await;
    assert!(login_result.is_ok());
}

#[tokio::test]
async fn test_refresh_token() {
    let service = test_service();
    let req = valid_register_request();
    
    // Register and get token
    let auth = service.register(req).await.unwrap();
    
    // Refresh token
    let result = service.refresh_token(&auth.token).await;
    assert!(result.is_ok());
    
    let new_token = result.unwrap();
    assert!(!new_token.is_empty());
    assert_ne!(new_token, auth.token); // Should be different
}

#[tokio::test]
async fn test_get_user_by_token() {
    let service = test_service();
    let req = valid_register_request();
    
    // Register and get token
    let auth = service.register(req).await.unwrap();
    
    // Get user by token
    let result = service.get_user_by_token(&auth.token).await;
    assert!(result.is_ok());
    
    let user = result.unwrap();
    assert_eq!(user.email, auth.user.email);
    assert_eq!(user.username, auth.user.username);
}

#[tokio::test]
async fn test_cleanup_expired_tokens() {
    let service = test_service();
    
    let result = service.cleanup_expired_tokens().await;
    assert!(result.is_ok());
}

// ============= RSTest Tests =============

#[rstest]
#[case("user@example.com", "username1", "Password123")]
#[case("test.user@company.org", "test_user", "SecureP@ss456")]
#[case("admin+test@domain.co.uk", "admin123", "Str0ng!Pass")]
#[tokio::test]
async fn test_register_various_inputs(
    #[case] email: &str,
    #[case] username: &str,
    #[case] password: &str,
) {
    let service = test_service();
    let req = RegisterRequest {
        email: email.to_string(),
        username: username.to_string(),
        password: password.to_string(),
    };
    
    let result = service.register(req).await;
    assert!(result.is_ok());
    
    let auth = result.unwrap();
    assert_eq!(auth.user.email, email);
    assert_eq!(auth.user.username, username);
}

#[rstest]
#[case("invalid", "Email format is invalid")]
#[case("@example.com", "Email format is invalid")]
#[case("user@", "Email format is invalid")]
#[case("user example@test.com", "Email format is invalid")]
#[tokio::test]
async fn test_invalid_email_formats(
    #[case] email: &str,
    #[case] _expected_error: &str,
) {
    let service = test_service();
    let req = RegisterRequest {
        email: email.to_string(),
        username: "validuser".to_string(),
        password: "ValidPass123".to_string(),
    };
    
    let result = service.register(req).await;
    assert!(result.is_err());
}

#[rstest]
#[case(7, false)]
#[case(8, true)]
#[case(20, true)]
#[case(50, true)]
#[tokio::test]
async fn test_password_length_validation(
    #[case] length: usize,
    #[case] should_succeed: bool,
) {
    let service = test_service();
    let password = "A".repeat(length);
    let req = RegisterRequest {
        email: format!("user{}@example.com", length),
        username: format!("user{}", length),
        password,
    };
    
    let result = service.register(req).await;
    assert_eq!(result.is_ok(), should_succeed);
}

// ============= Test Case Tests =============

#[test_case("test@example.com", "testuser" => true ; "valid credentials")]
#[test_case("", "testuser" => false ; "empty email")]
#[test_case("test@example.com", "" => false ; "empty username")]
#[test_case("invalid-email", "testuser" => false ; "invalid email format")]
#[tokio::test]
async fn test_registration_validation(email: &str, username: &str) -> bool {
    let service = test_service();
    let req = RegisterRequest {
        email: email.to_string(),
        username: username.to_string(),
        password: "ValidPass123".to_string(),
    };
    
    service.register(req).await.is_ok()
}

#[test_case("test@example.com" => true ; "login with email")]
#[test_case("testuser" => true ; "login with username")]
#[test_case("nonexistent@example.com" => false ; "nonexistent email")]
#[test_case("nonexistentuser" => false ; "nonexistent username")]
#[tokio::test]
async fn test_login_variations(identity: &str) -> bool {
    let service = test_service();
    
    // Register a test user first
    let req = RegisterRequest {
        email: "test@example.com".to_string(),
        username: "testuser".to_string(),
        password: "ValidPass123".to_string(),
    };
    service.register(req).await.unwrap();
    
    // Try to login
    service.login(identity.to_string(), "ValidPass123".to_string()).await.is_ok()
}

// ============= Property Tests =============

proptest! {
    #[test]
    fn test_email_validation_property(email in "[a-z]{1,10}@[a-z]{1,10}\\.[a-z]{2,4}") {
        // This should always be a valid email format
        let re = regex::Regex::new(r"^[\w.+-]+@[\w-]+\.[\w.-]+$").unwrap();
        prop_assert!(re.is_match(&email));
    }
    
    #[test]
    fn test_password_hash_is_different_from_password(password in "[A-Za-z0-9!@#$%^&*]{8,50}") {
        use argon2::{Argon2, password_hash::{PasswordHasher, SaltString}};
        use rand::thread_rng;
        
        let salt = SaltString::generate(thread_rng());
        let argon2 = Argon2::default();
        
        if let Ok(hash) = argon2.hash_password(password.as_bytes(), &salt) {
            let hash_str = hash.to_string();
            prop_assert_ne!(password.clone(), hash_str.clone());
            prop_assert!(hash_str.len() > password.len());
        }
    }
    
    #[test]
    fn test_uuid_generation_is_unique(seed in 0u64..1000u64) {
        let uuid1 = Uuid::new_v4();
        let uuid2 = Uuid::new_v4();
        prop_assert_ne!(uuid1, uuid2);
    }
}

// ============= Edge Case Tests =============

#[tokio::test]
async fn test_concurrent_registrations() {
    let service = Arc::new(test_service());
    let mut handles = vec![];
    
    for i in 0..10 {
        let service_clone = Arc::clone(&service);
        let handle = tokio::spawn(async move {
            let req = RegisterRequest {
                email: format!("user{}@example.com", i),
                username: format!("user{}", i),
                password: "Password123".to_string(),
            };
            service_clone.register(req).await
        });
        handles.push(handle);
    }
    
    let results: Vec<_> = futures::future::join_all(handles).await;
    
    // All registrations should succeed
    for result in results {
        assert!(result.is_ok());
        assert!(result.unwrap().is_ok());
    }
}

#[tokio::test]
async fn test_database_failure_handling() {
    let user_repo = Arc::new(MockUserRepository::new());
    user_repo.set_should_fail(true);
    
    let group_repo = Arc::new(MockGroupRepository::new());
    let password_reset_repo = Arc::new(MockPasswordResetRepository::new());
    let jwt_service = Arc::new(JwtService::new("test_secret"));
    
    let service = UserService::new(user_repo, group_repo, password_reset_repo, jwt_service);
    
    let req = RegisterRequest {
        email: "test@example.com".to_string(),
        username: "testuser".to_string(),
        password: "Password123".to_string(),
    };
    
    let result = service.register(req).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("Database error"));
}

#[tokio::test]
async fn test_expired_reset_token() {
    let service = test_service();
    let password_reset_repo = Arc::new(MockPasswordResetRepository::new());
    
    // Create an expired token manually
    let expired_token = PasswordResetToken {
        token_id: 1,
        user_id: 1,
        token: "expired_token".to_string(),
        expires_at: Utc::now() - Duration::hours(1), // Expired 1 hour ago
        used_at: None,
        created_at: Utc::now() - Duration::hours(2),
    };
    password_reset_repo.tokens.lock().unwrap().push(expired_token);
    
    let reset_req = ResetPasswordRequest {
        token: "expired_token".to_string(),
        new_password: "NewPassword123".to_string(),
    };
    
    let group_repo = Arc::new(MockGroupRepository::new());
    let user_repo = Arc::new(MockUserRepository::new());
    let jwt_service = Arc::new(JwtService::new("test_secret"));
    let service = UserService::new(user_repo, group_repo, password_reset_repo, jwt_service);
    
    let result = service.reset_password(reset_req).await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().to_string(), "invalid or expired token");
}

#[tokio::test]
async fn test_used_reset_token() {
    let service = test_service();
    let req = valid_register_request();
    
    // Register user
    service.register(req.clone()).await.unwrap();
    
    // Request password reset
    let forgot_req = ForgotPasswordRequest {
        email: req.email.clone(),
    };
    let token = service.forgot_password(forgot_req).await.unwrap();
    
    // Use the token once
    let reset_req = ResetPasswordRequest {
        token: token.clone(),
        new_password: "NewPassword123".to_string(),
    };
    assert!(service.reset_password(reset_req.clone()).await.is_ok());
    
    // Try to use the same token again
    let result = service.reset_password(reset_req).await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().to_string(), "invalid or expired token");
}

#[tokio::test]
async fn test_special_characters_in_username() {
    let service = test_service();
    
    let special_usernames = vec![
        "user_123",
        "user-test",
        "user.name",
        "123user",
        "USER",
    ];
    
    for (i, username) in special_usernames.iter().enumerate() {
        let req = RegisterRequest {
            email: format!("user{}@example.com", i),
            username: username.to_string(),
            password: "Password123".to_string(),
        };
        
        let result = service.register(req).await;
        assert!(result.is_ok(), "Failed for username: {}", username);
    }
}

#[tokio::test]
async fn test_very_long_inputs() {
    let service = test_service();
    
    // Test with very long but valid inputs
    let long_username = "u".repeat(50);
    let long_password = "P@ssw0rd".repeat(10); // 80 characters
    
    let req = RegisterRequest {
        email: format!("{}@example.com", "a".repeat(50)),
        username: long_username.clone(),
        password: long_password,
    };
    
    let result = service.register(req).await;
    assert!(result.is_ok());
    
    let auth = result.unwrap();
    assert_eq!(auth.user.username, long_username);
}

#[tokio::test]
async fn test_user_groups_assignment() {
    let user_repo = Arc::new(MockUserRepository::new());
    let group_repo = Arc::new(MockGroupRepository::new());
    let password_reset_repo = Arc::new(MockPasswordResetRepository::new());
    let jwt_service = Arc::new(JwtService::new("test_secret"));
    
    let service = UserService::new(
        user_repo.clone(),
        group_repo.clone(),
        password_reset_repo,
        jwt_service,
    );
    
    // Register user
    let req = RegisterRequest {
        email: "test@example.com".to_string(),
        username: "testuser".to_string(),
        password: "Password123".to_string(),
    };
    let auth = service.register(req).await.unwrap();
    
    // Add user to group manually (simulating admin action)
    user_repo.groups.lock().unwrap().push((auth.user.user_id, 1));
    user_repo.groups.lock().unwrap().push((auth.user.user_id, 2));
    
    // Get user groups
    let groups = user_repo.get_user_groups(auth.user.user_id).await.unwrap();
    assert_eq!(groups.len(), 2);
}

// ============= Integration-like Tests =============

#[tokio::test]
async fn test_complete_user_lifecycle() {
    let service = test_service();
    
    // 1. Register new user
    let register_req = RegisterRequest {
        email: "lifecycle@example.com".to_string(),
        username: "lifecycle_user".to_string(),
        password: "InitialPass123".to_string(),
    };
    let auth = service.register(register_req.clone()).await.unwrap();
    assert!(!auth.token.is_empty());
    
    // 2. Login with email
    let login_result = service.login(
        "lifecycle@example.com".to_string(),
        "InitialPass123".to_string()
    ).await;
    assert!(login_result.is_ok());
    
    // 3. Login with username
    let login_result = service.login(
        "lifecycle_user".to_string(),
        "InitialPass123".to_string()
    ).await;
    assert!(login_result.is_ok());
    
    // 4. Change password
    let change_req = ChangePasswordRequest {
        current_password: "InitialPass123".to_string(),
        new_password: "UpdatedPass456".to_string(),
    };
    service.change_password(auth.user.user_id, change_req).await.unwrap();
    
    // 5. Verify old password doesn't work
    let old_login = service.login(
        "lifecycle@example.com".to_string(),
        "InitialPass123".to_string()
    ).await;
    assert!(old_login.is_err());
    
    // 6. Verify new password works
    let new_login = service.login(
        "lifecycle@example.com".to_string(),
        "UpdatedPass456".to_string()
    ).await;
    assert!(new_login.is_ok());
    
    // 7. Request password reset
    let forgot_req = ForgotPasswordRequest {
        email: "lifecycle@example.com".to_string(),
    };
    let reset_token = service.forgot_password(forgot_req).await.unwrap();
    
    // 8. Reset password
    let reset_req = ResetPasswordRequest {
        token: reset_token,
        new_password: "FinalPass789".to_string(),
    };
    service.reset_password(reset_req).await.unwrap();
    
    // 9. Login with final password
    let final_login = service.login(
        "lifecycle@example.com".to_string(),
        "FinalPass789".to_string()
    ).await;
    assert!(final_login.is_ok());
    
    // 10. Refresh token
    let new_token = service.refresh_token(&final_login.unwrap().token).await.unwrap();
    assert!(!new_token.is_empty());
    
    // 11. Get user by token
    let user_from_token = service.get_user_by_token(&new_token).await.unwrap();
    assert_eq!(user_from_token.email, "lifecycle@example.com");
}
