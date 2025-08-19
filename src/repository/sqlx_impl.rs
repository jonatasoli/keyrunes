use super::{NewUser, User, UserRepository};
use anyhow::Result;
use async_trait::async_trait;
use sqlx::PgPool;

pub struct PgUserRepository {
    pub pool: PgPool,
}

impl PgUserRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl UserRepository for PgUserRepository {
    async fn find_by_email(&self, email: &str) -> Result<Option<User>> {
        let rec = sqlx::query_as!(
            User,
            r#"SELECT user_id, external_id, email, username, password_hash FROM users WHERE email = $1"#,
            email
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(rec)
    }

    async fn find_by_username(&self, username: &str) -> Result<Option<User>> {
        let rec = sqlx::query_as!(
            User,
            r#"SELECT user_id, external_id, email, username, password_hash FROM users WHERE username = $1"#,
            username
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(rec)
    }

    async fn insert_user(&self, new_user: NewUser) -> Result<User> {
        let rec = sqlx::query_as!(
            User,
            r#"INSERT INTO users (external_id, email, username, password_hash) VALUES ($1, $2, $3, $4) RETURNING user_id, external_id, email, username, password_hash"#,
            new_user.external_id,
            new_user.email,
            new_user.username,
            new_user.password_hash
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(rec)
    }
}
