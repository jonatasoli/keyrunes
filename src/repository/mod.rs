use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct User {
    pub user_id: i64,
    pub external_id: Uuid,
    pub email: String,
    pub username: String,
    pub password_hash: String,
}

#[derive(Debug, Clone)]
pub struct NewUser {
    pub external_id: Uuid,
    pub email: String,
    pub username: String,
    pub password_hash: String,
}

#[async_trait]
pub trait UserRepository: Send + Sync + 'static {
    async fn find_by_email(&self, email: &str) -> Result<Option<User>>;
    async fn find_by_username(&self, username: &str) -> Result<Option<User>>;
    async fn insert_user(&self, new_user: NewUser) -> Result<User>;
}

pub mod sqlx_impl;
