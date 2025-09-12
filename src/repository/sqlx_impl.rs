use super::*;
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
            r#"SELECT user_id, external_id, email, username, password_hash, created_at, first_login, updated_at  FROM users WHERE email = $1"#,
            email
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(rec)
    }

    async fn find_by_username(&self, username: &str) -> Result<Option<User>> {
        let rec = sqlx::query_as!(
            User,
            r#"SELECT user_id, external_id, email, username, password_hash, created_at, first_login, updated_at FROM users WHERE username = $1"#,
            username
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(rec)
    }

    async fn find_by_id(&self, user_id: i64) -> Result<Option<User>> {
        let rec = sqlx::query_as!(
            User,
            r#"SELECT user_id, external_id, email, username, password_hash, first_login, created_at, updated_at FROM users WHERE user_id = $1"#,
            user_id
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(rec)
    }

    async fn insert_user(&self, new_user: NewUser) -> Result<User> {
        let rec = sqlx::query_as!(
            User,
            r#"INSERT INTO users (external_id, email, username, password_hash, first_login) VALUES ($1, $2, $3, $4, $5) RETURNING user_id, external_id, email, username, password_hash, first_login, created_at, updated_at"#,
            new_user.external_id,
            new_user.email,
            new_user.username,
            new_user.password_hash,
            new_user.first_login
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(rec)
    }

    async fn update_user_password(&self, user_id: i64, new_password_hash: &str) -> Result<()> {
        sqlx::query!(
            "UPDATE users SET password_hash = $1, updated_at = now() WHERE user_id = $2",
            new_password_hash,
            user_id
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn set_first_login(&self, user_id: i64, first_login: bool) -> Result<()> {
        sqlx::query!(
            "UPDATE users SET first_login = $1, updated_at = now() WHERE user_id = $2",
            first_login,
            user_id
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_user_groups(&self, user_id: i64) -> Result<Vec<Group>> {
        let groups = sqlx::query_as!(
            Group,
            r#"SELECT g.group_id, g.external_id, g.name, g.description, g.created_at, g.updated_at
               FROM groups g
               INNER JOIN user_groups ug ON g.group_id = ug.group_id
               WHERE ug.user_id = $1"#,
            user_id
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(groups)
    }

    async fn get_user_policies(&self, user_id: i64) -> Result<Vec<Policy>> {
        let policies = sqlx::query!(
            r#"SELECT p.policy_id, p.external_id, p.name, p.description, p.resource, p.action, 
               p.effect as "effect_str", p.conditions, p.created_at, p.updated_at
               FROM policies p
               INNER JOIN user_policies up ON p.policy_id = up.policy_id
               WHERE up.user_id = $1"#,
            user_id
        )
        .fetch_all(&self.pool)
        .await?;

        let mut result = Vec::new();
        for row in policies {
            let effect = match row.effect_str.as_str() {
                "ALLOW" => PolicyEffect::Allow,
                "DENY" => PolicyEffect::Deny,
                _ => PolicyEffect::Deny,
            };

            result.push(Policy {
                policy_id: row.policy_id,
                external_id: row.external_id,
                name: row.name,
                description: row.description,
                resource: row.resource,
                action: row.action,
                effect,
                conditions: row.conditions,
                created_at: row.created_at,
                updated_at: row.updated_at,
            });
        }
        Ok(result)
    }

    async fn get_user_all_policies(&self, user_id: i64) -> Result<Vec<Policy>> {
        let policies = sqlx::query!(
            r#"SELECT DISTINCT p.policy_id, p.external_id, p.name, p.description, p.resource, p.action, 
               p.effect as "effect_str", p.conditions, p.created_at, p.updated_at
               FROM policies p
               LEFT JOIN user_policies up ON p.policy_id = up.policy_id AND up.user_id = $1
               LEFT JOIN group_policies gp ON p.policy_id = gp.policy_id
               LEFT JOIN user_groups ug ON gp.group_id = ug.group_id AND ug.user_id = $1
               WHERE up.user_id IS NOT NULL OR ug.user_id IS NOT NULL"#,
            user_id
        )
        .fetch_all(&self.pool)
        .await?;

        let mut result = Vec::new();
        for row in policies {
            let effect = match row.effect_str.as_str() {
                "ALLOW" => PolicyEffect::Allow,
                "DENY" => PolicyEffect::Deny,
                _ => PolicyEffect::Deny,
            };

            result.push(Policy {
                policy_id: row.policy_id,
                external_id: row.external_id,
                name: row.name,
                description: row.description,
                resource: row.resource,
                action: row.action,
                effect,
                conditions: row.conditions,
                created_at: row.created_at,
                updated_at: row.updated_at,
            });
        }
        Ok(result)
    }
}

pub struct PgGroupRepository {
    pub pool: PgPool,
}

impl PgGroupRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl GroupRepository for PgGroupRepository {
    async fn find_by_name(&self, name: &str) -> Result<Option<Group>> {
        let rec = sqlx::query_as!(
            Group,
            r#"SELECT group_id, external_id, name, description, created_at, updated_at FROM groups WHERE name = $1"#,
            name
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(rec)
    }

    async fn find_by_id(&self, group_id: i64) -> Result<Option<Group>> {
        let rec = sqlx::query_as!(
            Group,
            r#"SELECT group_id, external_id, name, description, created_at, updated_at FROM groups WHERE group_id = $1"#,
            group_id
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(rec)
    }

    async fn insert_group(&self, new_group: NewGroup) -> Result<Group> {
        let rec = sqlx::query_as!(
            Group,
            r#"INSERT INTO groups (external_id, name, description) 
               VALUES ($1, $2, $3) 
               RETURNING group_id, external_id, name, description, created_at, updated_at"#,
            new_group.external_id,
            new_group.name,
            new_group.description
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(rec)
    }

    async fn list_groups(&self) -> Result<Vec<Group>> {
        let groups = sqlx::query_as!(
            Group,
            r#"SELECT group_id, external_id, name, description, created_at, updated_at FROM groups ORDER BY name"#
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(groups)
    }

    async fn assign_user_to_group(
        &self,
        user_id: i64,
        group_id: i64,
        assigned_by: Option<i64>,
    ) -> Result<()> {
        sqlx::query!(
            "INSERT INTO user_groups (user_id, group_id, assigned_by) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
            user_id,
            group_id,
            assigned_by
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn remove_user_from_group(&self, user_id: i64, group_id: i64) -> Result<()> {
        sqlx::query!(
            "DELETE FROM user_groups WHERE user_id = $1 AND group_id = $2",
            user_id,
            group_id
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_group_policies(&self, group_id: i64) -> Result<Vec<Policy>> {
        let policies = sqlx::query!(
            r#"SELECT p.policy_id, p.external_id, p.name, p.description, p.resource, p.action, 
               p.effect as "effect_str", p.conditions, p.created_at, p.updated_at
               FROM policies p
               INNER JOIN group_policies gp ON p.policy_id = gp.policy_id
               WHERE gp.group_id = $1"#,
            group_id
        )
        .fetch_all(&self.pool)
        .await?;

        let mut result = Vec::new();
        for row in policies {
            let effect = match row.effect_str.as_str() {
                "ALLOW" => PolicyEffect::Allow,
                "DENY" => PolicyEffect::Deny,
                _ => PolicyEffect::Deny,
            };

            result.push(Policy {
                policy_id: row.policy_id,
                external_id: row.external_id,
                name: row.name,
                description: row.description,
                resource: row.resource,
                action: row.action,
                effect,
                conditions: row.conditions,
                created_at: row.created_at,
                updated_at: row.updated_at,
            });
        }
        Ok(result)
    }
}

pub struct PgPolicyRepository {
    pub pool: PgPool,
}

impl PgPolicyRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl PolicyRepository for PgPolicyRepository {
    async fn find_by_name(&self, name: &str) -> Result<Option<Policy>> {
        let row = sqlx::query!(
            r#"SELECT policy_id, external_id, name, description, resource, action, 
               effect as "effect_str", conditions, created_at, updated_at 
               FROM policies WHERE name = $1"#,
            name
        )
        .fetch_optional(&self.pool)
        .await?;

        if let Some(row) = row {
            let effect = match row.effect_str.as_str() {
                "ALLOW" => PolicyEffect::Allow,
                "DENY" => PolicyEffect::Deny,
                _ => PolicyEffect::Deny,
            };

            Ok(Some(Policy {
                policy_id: row.policy_id,
                external_id: row.external_id,
                name: row.name,
                description: row.description,
                resource: row.resource,
                action: row.action,
                effect,
                conditions: row.conditions,
                created_at: row.created_at,
                updated_at: row.updated_at,
            }))
        } else {
            Ok(None)
        }
    }

    async fn find_by_id(&self, policy_id: i64) -> Result<Option<Policy>> {
        let row = sqlx::query!(
            r#"SELECT policy_id, external_id, name, description, resource, action, 
               effect as "effect_str", conditions, created_at, updated_at 
               FROM policies WHERE policy_id = $1"#,
            policy_id
        )
        .fetch_optional(&self.pool)
        .await?;

        if let Some(row) = row {
            let effect = match row.effect_str.as_str() {
                "ALLOW" => PolicyEffect::Allow,
                "DENY" => PolicyEffect::Deny,
                _ => PolicyEffect::Deny,
            };

            Ok(Some(Policy {
                policy_id: row.policy_id,
                external_id: row.external_id,
                name: row.name,
                description: row.description,
                resource: row.resource,
                action: row.action,
                effect,
                conditions: row.conditions,
                created_at: row.created_at,
                updated_at: row.updated_at,
            }))
        } else {
            Ok(None)
        }
    }

    async fn insert_policy(&self, new_policy: NewPolicy) -> Result<Policy> {
        let effect_str = new_policy.effect.to_string();
        let row = sqlx::query!(
            r#"INSERT INTO policies (external_id, name, description, resource, action, effect, conditions) 
               VALUES ($1, $2, $3, $4, $5, $6, $7) 
               RETURNING policy_id, external_id, name, description, resource, action, 
               effect as "effect_str", conditions, created_at, updated_at"#,
            new_policy.external_id,
            new_policy.name,
            new_policy.description,
            new_policy.resource,
            new_policy.action,
            effect_str,
            new_policy.conditions
        )
        .fetch_one(&self.pool)
        .await?;

        let effect = match row.effect_str.as_str() {
            "ALLOW" => PolicyEffect::Allow,
            "DENY" => PolicyEffect::Deny,
            _ => PolicyEffect::Deny,
        };

        Ok(Policy {
            policy_id: row.policy_id,
            external_id: row.external_id,
            name: row.name,
            description: row.description,
            resource: row.resource,
            action: row.action,
            effect,
            conditions: row.conditions,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }

    async fn list_policies(&self) -> Result<Vec<Policy>> {
        let rows = sqlx::query!(
            r#"SELECT policy_id, external_id, name, description, resource, action, 
               effect as "effect_str", conditions, created_at, updated_at 
               FROM policies ORDER BY name"#
        )
        .fetch_all(&self.pool)
        .await?;

        let mut result = Vec::new();
        for row in rows {
            let effect = match row.effect_str.as_str() {
                "ALLOW" => PolicyEffect::Allow,
                "DENY" => PolicyEffect::Deny,
                _ => PolicyEffect::Deny,
            };

            result.push(Policy {
                policy_id: row.policy_id,
                external_id: row.external_id,
                name: row.name,
                description: row.description,
                resource: row.resource,
                action: row.action,
                effect,
                conditions: row.conditions,
                created_at: row.created_at,
                updated_at: row.updated_at,
            });
        }
        Ok(result)
    }

    async fn assign_policy_to_user(
        &self,
        user_id: i64,
        policy_id: i64,
        assigned_by: Option<i64>,
    ) -> Result<()> {
        sqlx::query!(
            "INSERT INTO user_policies (user_id, policy_id, assigned_by) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
            user_id,
            policy_id,
            assigned_by
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn assign_policy_to_group(
        &self,
        group_id: i64,
        policy_id: i64,
        assigned_by: Option<i64>,
    ) -> Result<()> {
        sqlx::query!(
            "INSERT INTO group_policies (group_id, policy_id, assigned_by) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
            group_id,
            policy_id,
            assigned_by
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn remove_policy_from_user(&self, user_id: i64, policy_id: i64) -> Result<()> {
        sqlx::query!(
            "DELETE FROM user_policies WHERE user_id = $1 AND policy_id = $2",
            user_id,
            policy_id
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn remove_policy_from_group(&self, group_id: i64, policy_id: i64) -> Result<()> {
        sqlx::query!(
            "DELETE FROM group_policies WHERE group_id = $1 AND policy_id = $2",
            group_id,
            policy_id
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

pub struct PgPasswordResetRepository {
    pub pool: PgPool,
}

impl PgPasswordResetRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl PasswordResetRepository for PgPasswordResetRepository {
    async fn create_reset_token(&self, token: NewPasswordResetToken) -> Result<PasswordResetToken> {
        let rec = sqlx::query_as!(
            PasswordResetToken,
            r#"INSERT INTO password_reset_tokens (user_id, token, expires_at) 
               VALUES ($1, $2, $3) 
               RETURNING token_id, user_id, token, expires_at, used_at, created_at"#,
            token.user_id,
            token.token,
            token.expires_at
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(rec)
    }

    async fn find_valid_token(&self, token: &str) -> Result<Option<PasswordResetToken>> {
        let rec = sqlx::query_as!(
            PasswordResetToken,
            r#"SELECT token_id, user_id, token, expires_at, used_at, created_at 
               FROM password_reset_tokens 
               WHERE token = $1 AND expires_at > now() AND used_at IS NULL"#,
            token
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(rec)
    }

    async fn mark_token_used(&self, token_id: i64) -> Result<()> {
        sqlx::query!(
            "UPDATE password_reset_tokens SET used_at = now() WHERE token_id = $1",
            token_id
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn cleanup_expired_tokens(&self) -> Result<()> {
        sqlx::query!("DELETE FROM password_reset_tokens WHERE expires_at < now()")
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}
