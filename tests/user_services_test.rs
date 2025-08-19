use anyhow::Result;
use async_trait::async_trait;
use keyrunes::repository::{NewUser, User, UserRepository};
use keyrunes::services::user_service::{RegisterRequest, UserService};
use std::sync::{Arc, Mutex};
use uuid::Uuid;

// Mock repository
struct MockRepo {
    users: Mutex<Vec<User>>,
}

impl MockRepo {
    fn new() -> Self {
        Self {
            users: Mutex::new(Vec::new()),
        }
    }
}

#[async_trait]
impl UserRepository for MockRepo {
    async fn find_by_email(&self, email: &str) -> Result<Option<User>> {
        let users = self.users.lock().unwrap();
        Ok(users.iter().cloned().find(|u| u.email == email))
    }

    async fn find_by_username(&self, username: &str) -> Result<Option<User>> {
        let users = self.users.lock().unwrap();
        Ok(users.iter().cloned().find(|u| u.username == username))
    }

    async fn insert_user(&self, new_user: NewUser) -> Result<User> {
        let user = User {
            user_id: (self.users.lock().unwrap().len() + 1) as i64,
            external_id: new_user.external_id,
            email: new_user.email,
            username: new_user.username,
            password_hash: new_user.password_hash,
        };
        self.users.lock().unwrap().push(user.clone());
        Ok(user)
    }
}

#[tokio::test]
async fn test_register_and_login() {
    // Setup
    let repo = Arc::new(MockRepo::new());
    let service = UserService::new(repo.clone());

    let req = RegisterRequest {
        email: "john@example.com".to_string(),
        username: "johndoe".to_string(),
        password: "Password123".to_string(),
    };

    // Act - Assert
    let user = service.register(req.clone()).await.unwrap();
    assert_eq!(user.email, "john@example.com");
    assert_eq!(user.username, "johndoe");

    // Act - Assert
    let login_user = service
        .login("john@example.com".to_string(), "Password123".to_string())
        .await
        .unwrap();
    assert_eq!(login_user.username, "johndoe");

    // Act - Assert
    let login_user2 = service
        .login("johndoe".to_string(), "Password123".to_string())
        .await
        .unwrap();
    assert_eq!(login_user2.email, "john@example.com");

    // Act - Assert
    let err = service
        .login("johndoe".to_string(), "wrongpass".to_string())
        .await
        .unwrap_err();
    assert_eq!(err.to_string(), "invalid credentials");
}
