use anyhow::{Result, anyhow};
use chrono::{Duration, Utc};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,         // Subject (user_id)
    pub email: String,       // User email
    pub username: String,    // Username
    pub groups: Vec<String>, // User groups
    pub exp: i64,            // Expiration time
    pub iat: i64,            // Issued at
    pub iss: String,         // Issuer
}

#[derive(Clone)]
pub struct JwtService {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    issuer: String,
}

impl JwtService {
    pub fn new(secret: &str) -> Self {
        Self {
            encoding_key: EncodingKey::from_secret(secret.as_ref()),
            decoding_key: DecodingKey::from_secret(secret.as_ref()),
            issuer: "keyrunes".to_string(),
        }
    }

    pub fn generate_token(
        &self,
        user_id: i64,
        email: &str,
        username: &str,
        groups: Vec<String>,
    ) -> Result<String> {
        let now = Utc::now();
        let exp = now + Duration::hours(1); // Token expires in 1 hour

        let claims = Claims {
            sub: user_id.to_string(),
            email: email.to_string(),
            username: username.to_string(),
            groups,
            exp: exp.timestamp(),
            iat: now.timestamp(),
            iss: self.issuer.clone(),
        };

        encode(&Header::default(), &claims, &self.encoding_key)
            .map_err(|e| anyhow!("Failed to encode JWT: {}", e))
    }

    pub fn verify_token(&self, token: &str) -> Result<Claims> {
        let token_data = decode::<Claims>(
            token,
            &self.decoding_key,
            &Validation::new(Algorithm::HS256),
        )
        .map_err(|e| anyhow!("Failed to decode JWT: {}", e))?;

        Ok(token_data.claims)
    }

    pub fn refresh_token(&self, token: &str) -> Result<String> {
        let claims = self.verify_token(token)?;

        // Generate new token with same claims but updated expiration
        self.generate_token(
            claims.sub.parse()?,
            &claims.email,
            &claims.username,
            claims.groups,
        )
    }

    pub fn extract_user_id(&self, token: &str) -> Result<i64> {
        let claims = self.verify_token(token)?;
        claims
            .sub
            .parse()
            .map_err(|e| anyhow!("Invalid user ID in token: {}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jwt_token_generation_and_verification() {
        let service = JwtService::new("test_secret");
        let groups = vec!["users".to_string(), "admin".to_string()];

        let token = service
            .generate_token(1, "test@example.com", "testuser", groups.clone())
            .unwrap();
        let claims = service.verify_token(&token).unwrap();

        assert_eq!(claims.sub, "1");
        assert_eq!(claims.email, "test@example.com");
        assert_eq!(claims.username, "testuser");
        assert_eq!(claims.groups, groups);
        assert_eq!(claims.iss, "keyrunes");
    }

    #[test]
    fn test_refresh_token() {
        let service = JwtService::new("test_secret");
        let groups = vec!["users".to_string()];

        let original_token = service
            .generate_token(1, "test@example.com", "testuser", groups)
            .unwrap();
        let refreshed_token = service.refresh_token(&original_token).unwrap();

        let original_claims = service.verify_token(&original_token).unwrap();
        let refreshed_claims = service.verify_token(&refreshed_token).unwrap();

        assert_eq!(original_claims.sub, refreshed_claims.sub);
        assert_eq!(original_claims.email, refreshed_claims.email);
        assert!(refreshed_claims.exp > original_claims.exp);
    }

    #[test]
    fn test_extract_user_id() {
        let service = JwtService::new("test_secret");
        let groups = vec!["users".to_string()];

        let token = service
            .generate_token(42, "test@example.com", "testuser", groups)
            .unwrap();
        let user_id = service.extract_user_id(&token).unwrap();

        assert_eq!(user_id, 42);
    }
}
