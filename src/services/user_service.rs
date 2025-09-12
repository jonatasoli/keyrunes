use crate::repository::{
    GroupRepository, NewPasswordResetToken, NewUser, PasswordResetRepository, UserRepository,
};
use crate::services::jwt_service::JwtService;
use anyhow::{Result, anyhow};
use argon2::{
    Argon2,
    password_hash::{PasswordHasher, SaltString},
};
use chrono::{Duration, Utc};
use password_hash::{PasswordHash, PasswordVerifier};
use rand::{Rng, thread_rng};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct RegisterRequest {
    pub email: String,
    pub username: String,
    pub password: String,
    pub first_login: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuthResponse {
    pub user: UserResponse,
    pub token: String,
    pub requires_password_change: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct UserResponse {
    pub user_id: i64,
    pub external_id: Uuid,
    pub email: String,
    pub username: String,
    pub groups: Vec<String>,
    pub first_login: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ForgotPasswordRequest {
    pub email: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ResetPasswordRequest {
    pub token: String,
    pub new_password: String,
}

#[derive(Clone)]
pub struct UserService<U: UserRepository, G: GroupRepository, P: PasswordResetRepository> {
    pub user_repo: Arc<U>,
    pub group_repo: Arc<G>,
    pub password_reset_repo: Arc<P>,
    pub jwt_service: Arc<JwtService>,
}

impl<U: UserRepository, G: GroupRepository, P: PasswordResetRepository> UserService<U, G, P> {
    pub fn new(
        user_repo: Arc<U>,
        group_repo: Arc<G>,
        password_reset_repo: Arc<P>,
        jwt_service: Arc<JwtService>,
    ) -> Self {
        Self {
            user_repo,
            group_repo,
            password_reset_repo,
            jwt_service,
        }
    }

    pub async fn register(&self, req: RegisterRequest) -> Result<AuthResponse> {
        // Validations
        let email_re = Regex::new(r"^[\w.+-]+@[\w-]+\.[\w.-]+$").unwrap();
        if !email_re.is_match(&req.email) {
            return Err(anyhow!("invalid email"));
        }
        if req.password.len() < 8 {
            return Err(anyhow!("password too short"));
        }

        // Check uniqueness
        if self.user_repo.find_by_email(&req.email).await?.is_some() {
            return Err(anyhow!("email already registered"));
        }
        if self
            .user_repo
            .find_by_username(&req.username)
            .await?
            .is_some()
        {
            return Err(anyhow!("username taken"));
        }

        // Hash password
        let password_hash = self.hash_password(&req.password)?;

        let new_user = NewUser {
            external_id: Uuid::new_v4(),
            email: req.email,
            username: req.username,
            password_hash,
            first_login: false,
        };

        let user = self.user_repo.insert_user(new_user).await?;

        // Assign to 'users' group by default
        if let Ok(Some(users_group)) = self.group_repo.find_by_name("users").await {
            let _ = self
                .group_repo
                .assign_user_to_group(user.user_id, users_group.group_id, None)
                .await;
        }

        // Get user groups for JWT
        let groups = self.get_user_group_names(user.user_id).await?;

        // Generate JWT token
        let token = self.jwt_service.generate_token(
            user.user_id,
            &user.email,
            &user.username,
            groups.clone(),
        )?;

        Ok(AuthResponse {
            user: UserResponse {
                user_id: user.user_id,
                external_id: user.external_id,
                email: user.email,
                username: user.username,
                groups,
                first_login: user.first_login,
            },
            token,
            requires_password_change: user.first_login,
        })
    }

    pub async fn login(&self, identity: String, password: String) -> Result<AuthResponse> {
        let email_re = Regex::new(r"^[\w.+-]+@[\w-]+\.[\w.-]+$").unwrap();
        let user_opt = if email_re.is_match(&identity) {
            self.user_repo.find_by_email(&identity).await?
        } else {
            self.user_repo.find_by_username(&identity).await?
        };

        let user = user_opt.ok_or_else(|| anyhow!("invalid credentials"))?;

        let parsed_hash = PasswordHash::new(&user.password_hash)
            .map_err(|_| anyhow!("invalid stored password hash"))?;
        let argon2 = Argon2::default();

        if argon2
            .verify_password(password.as_bytes(), &parsed_hash)
            .is_err()
        {
            return Err(anyhow!("invalid credentials"));
        }

        // Get user groups for JWT
        let groups = self.get_user_group_names(user.user_id).await?;

        // Generate JWT token
        let token = self.jwt_service.generate_token(
            user.user_id,
            &user.email,
            &user.username,
            groups.clone(),
        )?;

        Ok(AuthResponse {
            user: UserResponse {
                user_id: user.user_id,
                external_id: user.external_id,
                email: user.email,
                username: user.username,
                groups,
                first_login: user.first_login,
            },
            token,
            requires_password_change: user.first_login,
        })
    }

    pub async fn change_password(&self, user_id: i64, req: ChangePasswordRequest) -> Result<()> {
        let user = self
            .user_repo
            .find_by_id(user_id)
            .await?
            .ok_or_else(|| anyhow!("user not found"))?;

        // Verify current password
        let parsed_hash = PasswordHash::new(&user.password_hash)
            .map_err(|_| anyhow!("invalid stored password hash"))?;
        let argon2 = Argon2::default();

        if argon2
            .verify_password(req.current_password.as_bytes(), &parsed_hash)
            .is_err()
        {
            return Err(anyhow!("current password is incorrect"));
        }

        // Validate new password
        if req.new_password.len() < 8 {
            return Err(anyhow!("new password too short"));
        }

        // Hash new password
        let new_password_hash = self.hash_password(&req.new_password)?;

        // Update password and set first_login to false
        self.user_repo
            .update_user_password(user_id, &new_password_hash)
            .await?;
        self.user_repo.set_first_login(user_id, false).await?;

        Ok(())
    }

    pub async fn forgot_password(&self, req: ForgotPasswordRequest) -> Result<String> {
        let user = self
            .user_repo
            .find_by_email(&req.email)
            .await?
            .ok_or_else(|| anyhow!("email not found"))?;

        // Generate reset token
        let token = self.generate_reset_token();
        let expires_at = Utc::now() + Duration::hours(24); // Token valid for 24 hours

        let reset_token = NewPasswordResetToken {
            user_id: user.user_id,
            token: token.clone(),
            expires_at,
        };

        self.password_reset_repo
            .create_reset_token(reset_token)
            .await?;

        Ok(token)
    }

    pub async fn reset_password(&self, req: ResetPasswordRequest) -> Result<()> {
        let reset_token = self
            .password_reset_repo
            .find_valid_token(&req.token)
            .await?
            .ok_or_else(|| anyhow!("invalid or expired token"))?;

        // Validate new password
        if req.new_password.len() < 8 {
            return Err(anyhow!("new password too short"));
        }

        // Hash new password
        let new_password_hash = self.hash_password(&req.new_password)?;

        // Update password
        self.user_repo
            .update_user_password(reset_token.user_id, &new_password_hash)
            .await?;

        // Mark token as used
        self.password_reset_repo
            .mark_token_used(reset_token.token_id)
            .await?;

        Ok(())
    }

    pub async fn refresh_token(&self, token: &str) -> Result<String> {
        self.jwt_service.refresh_token(token)
    }

    pub async fn get_user_by_token(&self, token: &str) -> Result<UserResponse> {
        let claims = self.jwt_service.verify_token(token)?;
        let user_id: i64 = claims.sub.parse()?;

        let user = self
            .user_repo
            .find_by_id(user_id)
            .await?
            .ok_or_else(|| anyhow!("user not found"))?;

        let groups = self.get_user_group_names(user.user_id).await?;

        Ok(UserResponse {
            user_id: user.user_id,
            external_id: user.external_id,
            email: user.email,
            username: user.username,
            groups,
            first_login: user.first_login,
        })
    }

    async fn get_user_group_names(&self, user_id: i64) -> Result<Vec<String>> {
        let groups = self.user_repo.get_user_groups(user_id).await?;
        Ok(groups.into_iter().map(|g| g.name).collect())
    }

    fn hash_password(&self, password: &str) -> Result<String> {
        let salt = SaltString::generate(thread_rng());
        let argon2 = Argon2::default();
        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| anyhow!(e))?
            .to_string();
        Ok(password_hash)
    }

    fn generate_reset_token(&self) -> String {
        let token_bytes: [u8; 32] = thread_rng().r#gen();
        hex::encode(token_bytes)
    }

    pub async fn cleanup_expired_tokens(&self) -> Result<()> {
        self.password_reset_repo.cleanup_expired_tokens().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repository::{Group, NewGroup, Policy, PolicyEffect};
    use anyhow::Result;
    use async_trait::async_trait;
    use chrono::{DateTime, Utc};
    use std::sync::{Arc, Mutex};
    use uuid::Uuid;

    // Mock implementations for testing
    struct MockUserRepository {
        users: Mutex<Vec<User>>,
        groups: Mutex<Vec<(i64, i64)>>, // (user_id, group_id)
    }

    impl MockUserRepository {
        fn new() -> Self {
            Self {
                users: Mutex::new(Vec::new()),
                groups: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait]
    impl UserRepository for MockUserRepository {
        async fn find_by_email(&self, email: &str) -> Result<Option<User>> {
            let users = self.users.lock().unwrap();
            Ok(users.iter().find(|u| u.email == email).cloned())
        }

        async fn find_by_username(&self, username: &str) -> Result<Option<User>> {
            let users = self.users.lock().unwrap();
            Ok(users.iter().find(|u| u.username == username).cloned())
        }

        async fn find_by_id(&self, user_id: i64) -> Result<Option<User>> {
            let users = self.users.lock().unwrap();
            Ok(users.iter().find(|u| u.user_id == user_id).cloned())
        }

        async fn insert_user(&self, new_user: NewUser) -> Result<User> {
            let mut users = self.users.lock().unwrap();
            let user = User {
                user_id: (users.len() + 1) as i64,
                external_id: new_user.external_id,
                email: new_user.email,
                username: new_user.username,
                password_hash: new_user.password_hash,
                first_login: new_user.first_login,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            };
            users.push(user.clone());
            Ok(user)
        }

        async fn update_user_password(&self, user_id: i64, new_password_hash: &str) -> Result<()> {
            let mut users = self.users.lock().unwrap();
            if let Some(user) = users.iter_mut().find(|u| u.user_id == user_id) {
                user.password_hash = new_password_hash.to_string();
                user.updated_at = Utc::now();
            }
            Ok(())
        }

        async fn set_first_login(&self, user_id: i64, first_login: bool) -> Result<()> {
            let mut users = self.users.lock().unwrap();
            if let Some(user) = users.iter_mut().find(|u| u.user_id == user_id) {
                user.first_login = first_login;
                user.updated_at = Utc::now();
            }
            Ok(())
        }

        async fn get_user_groups(&self, user_id: i64) -> Result<Vec<Group>> {
            let groups = self.groups.lock().unwrap();
            let user_groups: Vec<Group> = groups
                .iter()
                .filter(|(uid, _)| *uid == user_id)
                .map(|(_, gid)| Group {
                    group_id: *gid,
                    external_id: Uuid::new_v4(),
                    name: "users".to_string(),
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

    struct MockGroupRepository;

    #[async_trait]
    impl GroupRepository for MockGroupRepository {
        async fn find_by_name(&self, name: &str) -> Result<Option<Group>> {
            if name == "users" {
                Ok(Some(Group {
                    group_id: 1,
                    external_id: Uuid::new_v4(),
                    name: name.to_string(),
                    description: None,
                    created_at: Utc::now(),
                    updated_at: Utc::now(),
                }))
            } else {
                Ok(None)
            }
        }

        async fn find_by_id(&self, _group_id: i64) -> Result<Option<Group>> {
            Ok(None)
        }

        async fn insert_group(&self, _new_group: NewGroup) -> Result<Group> {
            unimplemented!()
        }

        async fn list_groups(&self) -> Result<Vec<Group>> {
            Ok(Vec::new())
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

    struct MockPasswordResetRepository;

    #[async_trait]
    impl PasswordResetRepository for MockPasswordResetRepository {
        async fn create_reset_token(
            &self,
            _token: NewPasswordResetToken,
        ) -> Result<crate::repository::PasswordResetToken> {
            unimplemented!()
        }

        async fn find_valid_token(
            &self,
            _token: &str,
        ) -> Result<Option<crate::repository::PasswordResetToken>> {
            Ok(None)
        }

        async fn mark_token_used(&self, _token_id: i64) -> Result<()> {
            Ok(())
        }

        async fn cleanup_expired_tokens(&self) -> Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_register_and_login_with_jwt() {
        let user_repo = Arc::new(MockUserRepository::new());
        let group_repo = Arc::new(MockGroupRepository);
        let password_reset_repo = Arc::new(MockPasswordResetRepository);
        let jwt_service = Arc::new(JwtService::new("test_secret"));

        let service = UserService::new(user_repo, group_repo, password_reset_repo, jwt_service);

        let req = RegisterRequest {
            email: "test@example.com".to_string(),
            username: "testuser".to_string(),
            password: "password123".to_string(),
        };

        // Test registration
        let auth_response = service.register(req).await.unwrap();
        assert_eq!(auth_response.user.email, "test@example.com");
        assert_eq!(auth_response.user.username, "testuser");
        assert!(!auth_response.token.is_empty());
        assert!(!auth_response.requires_password_change);

        // Test login
        let login_response = service
            .login("test@example.com".to_string(), "password123".to_string())
            .await
            .unwrap();
        assert_eq!(login_response.user.username, "testuser");
        assert!(!login_response.token.is_empty());
    }
}
