use anyhow::Result;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct User {
    pub user_id: i64,
    pub external_id: Uuid,
    pub email: String,
    pub username: String,
    pub password_hash: String,
    pub first_login: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct NewUser {
    pub external_id: Uuid,
    pub email: String,
    pub username: String,
    pub password_hash: String,
    pub first_login: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Group {
    pub group_id: i64,
    pub external_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct NewGroup {
    pub external_id: Uuid,
    pub name: String,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Policy {
    pub policy_id: i64,
    pub external_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub resource: String,
    pub action: String,
    pub effect: PolicyEffect,
    pub conditions: Option<JsonValue>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PolicyEffect {
    #[serde(rename = "ALLOW")]
    Allow,
    #[serde(rename = "DENY")]
    Deny,
}

impl std::fmt::Display for PolicyEffect {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PolicyEffect::Allow => write!(f, "ALLOW"),
            PolicyEffect::Deny => write!(f, "DENY"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct NewPolicy {
    pub external_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub resource: String,
    pub action: String,
    pub effect: PolicyEffect,
    pub conditions: Option<JsonValue>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserGroup {
    pub user_id: i64,
    pub group_id: i64,
    pub assigned_at: DateTime<Utc>,
    pub assigned_by: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserPolicy {
    pub user_id: i64,
    pub policy_id: i64,
    pub assigned_at: DateTime<Utc>,
    pub assigned_by: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupPolicy {
    pub group_id: i64,
    pub policy_id: i64,
    pub assigned_at: DateTime<Utc>,
    pub assigned_by: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordResetToken {
    pub token_id: i64,
    pub user_id: i64,
    pub token: String,
    pub expires_at: DateTime<Utc>,
    pub used_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct NewPasswordResetToken {
    pub user_id: i64,
    pub token: String,
    pub expires_at: DateTime<Utc>,
}

// User Repository Trait
#[async_trait]
pub trait UserRepository: Send + Sync + 'static {
    async fn find_by_email(&self, email: &str) -> Result<Option<User>>;
    async fn find_by_username(&self, username: &str) -> Result<Option<User>>;
    async fn find_by_id(&self, user_id: i64) -> Result<Option<User>>;
    async fn insert_user(&self, new_user: NewUser) -> Result<User>;
    async fn update_user_password(&self, user_id: i64, new_password_hash: &str) -> Result<()>;
    async fn set_first_login(&self, user_id: i64, first_login: bool) -> Result<()>;
    async fn get_user_groups(&self, user_id: i64) -> Result<Vec<Group>>;
    async fn get_user_policies(&self, user_id: i64) -> Result<Vec<Policy>>;
    async fn get_user_all_policies(&self, user_id: i64) -> Result<Vec<Policy>>;
}

// Group Repository Trait
#[async_trait]
pub trait GroupRepository: Send + Sync + 'static {
    async fn find_by_name(&self, name: &str) -> Result<Option<Group>>;
    async fn find_by_id(&self, group_id: i64) -> Result<Option<Group>>;
    async fn insert_group(&self, new_group: NewGroup) -> Result<Group>;
    async fn list_groups(&self) -> Result<Vec<Group>>;
    async fn assign_user_to_group(
        &self,
        user_id: i64,
        group_id: i64,
        assigned_by: Option<i64>,
    ) -> Result<()>;
    async fn assign_user_to_groups(
        &self,
        user_id: i64,
        group_ids: &[i64],
        assigned_by: Option<i64>,
    ) -> Result<()> {
        for group_id in group_ids {
            let _ = self
                .assign_user_to_group(user_id, *group_id, assigned_by)
                .await?;
        }
        Ok(())
    }
    async fn remove_user_from_group(&self, user_id: i64, group_id: i64) -> Result<()>;
    async fn get_group_policies(&self, group_id: i64) -> Result<Vec<Policy>>;
}

// Policy Repository Trait
#[async_trait]
pub trait PolicyRepository: Send + Sync + 'static {
    async fn find_by_name(&self, name: &str) -> Result<Option<Policy>>;
    async fn find_by_id(&self, policy_id: i64) -> Result<Option<Policy>>;
    async fn insert_policy(&self, new_policy: NewPolicy) -> Result<Policy>;
    async fn list_policies(&self) -> Result<Vec<Policy>>;
    async fn assign_policy_to_user(
        &self,
        user_id: i64,
        policy_id: i64,
        assigned_by: Option<i64>,
    ) -> Result<()>;
    async fn assign_policy_to_group(
        &self,
        group_id: i64,
        policy_id: i64,
        assigned_by: Option<i64>,
    ) -> Result<()>;
    async fn remove_policy_from_user(&self, user_id: i64, policy_id: i64) -> Result<()>;
    async fn remove_policy_from_group(&self, group_id: i64, policy_id: i64) -> Result<()>;
}

// Password Reset Repository Trait
#[async_trait]
pub trait PasswordResetRepository: Send + Sync + 'static {
    async fn create_reset_token(&self, token: NewPasswordResetToken) -> Result<PasswordResetToken>;
    async fn find_valid_token(&self, token: &str) -> Result<Option<PasswordResetToken>>;
    async fn mark_token_used(&self, token_id: i64) -> Result<()>;
    async fn cleanup_expired_tokens(&self) -> Result<()>;
}

pub mod sqlx_impl;
