use crate::repository::{NewUser, User, UserRepository};
use anyhow::{Result, anyhow};
use argon2::{
    Argon2,
    password_hash::{PasswordHasher, SaltString},
};
use password_hash::{PasswordHash, PasswordVerifier};
use regex::Regex;
use std::sync::Arc;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct RegisterRequest {
    pub email: String,
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone)]
pub struct UserService<R: UserRepository> {
    pub repo: Arc<R>,
}

impl<R: UserRepository> UserService<R> {
    pub fn new(repo: Arc<R>) -> Self {
        Self { repo }
    }

    pub async fn register(&self, req: RegisterRequest) -> Result<User> {
        // validations
        let email_re = Regex::new(r"^[\w.+-]+@[\w-]+\.[\w.-]+$").unwrap();
        if !email_re.is_match(&req.email) {
            return Err(anyhow!("invalid email"));
        }
        if req.password.len() < 8 {
            return Err(anyhow!("password too short"));
        }
        // check uniqueness
        if self.repo.find_by_email(&req.email).await?.is_some() {
            return Err(anyhow!("email already registered"));
        }
        if self.repo.find_by_username(&req.username).await?.is_some() {
            return Err(anyhow!("username taken"));
        }

        // hash password
        let salt = SaltString::generate(rand::thread_rng());
        let argon2 = Argon2::default();
        let password_hash = argon2
            .hash_password(req.password.as_bytes(), &salt)
            .map_err(|e| anyhow!(e))?
            .to_string();

        let new_user = NewUser {
            external_id: Uuid::new_v4(),
            email: req.email,
            username: req.username,
            password_hash,
        };

        let user = self.repo.insert_user(new_user).await?;
        Ok(user)
    }

    pub async fn login(&self, identity: String, password: String) -> Result<User> {
        let email_re = Regex::new(r"^[\w.+-]+@[\w-]+\.[\w.-]+$").unwrap();
        let user_opt = if email_re.is_match(&identity) {
            self.repo.find_by_email(&identity).await?
        } else {
            self.repo.find_by_username(&identity).await?
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

        Ok(user)
    }
}
