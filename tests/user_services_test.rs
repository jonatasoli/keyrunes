use anyhow::Result;
use async_trait::async_trait;
use chrono::Utc;
use keyrunes::UserGroup;
use keyrunes::domain::user::{Email, Password};
use keyrunes::group_service::{CreateGroupRequest, GroupService};
use keyrunes::repository::{Group, NewUser, Policy, User, UserRepository};
use keyrunes::services::user_service::{RegisterRequest, UserService};
use keyrunes::user_service::CreateUserRequest;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

type Store<T> = Arc<Mutex<Vec<T>>>;
type GroupStore = Store<Group>;
type UserGroupStore = Store<UserGroup>;

fn create_stores() -> (GroupStore, UserGroupStore) {
    let group_store = Arc::new(Mutex::new(Vec::new()));
    let user_group_store = Arc::new(Mutex::new(Vec::new()));

    // seed with admin and user groups
    group_store.lock().unwrap().push(Group {
        group_id: 0,
        external_id: Uuid::new_v4(),
        name: "superadmin".to_string(),
        description: Some("Admin group".to_string()),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    });

    group_store.lock().unwrap().push(Group {
        group_id: 1,
        external_id: Uuid::new_v4(),
        name: "users".to_string(),
        description: Some("User group".to_string()),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    });

    (group_store, user_group_store)
}

// Mock repository implementation
struct MockRepo {
    users: Mutex<Vec<User>>,
    group_store: GroupStore,
    user_group_store: UserGroupStore,
}

impl MockRepo {
    fn new(group_store: GroupStore, user_group_store: UserGroupStore) -> Self {
        Self {
            users: Mutex::new(Vec::new()),
            group_store,
            user_group_store,
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

    async fn find_by_id(&self, user_id: i64) -> Result<Option<User>> {
        let users = self.users.lock().unwrap();
        Ok(users.iter().cloned().find(|u| u.user_id == user_id))
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
        let groups = self.group_store.lock().unwrap();
        let user_groups = self.user_group_store.lock().unwrap();
        let user_groups: Vec<Group> = user_groups
            .iter()
            .filter(|ug| ug.user_id == user_id)
            .map(|ug| {
                groups
                    .iter()
                    .cloned()
                    .find(|g| ug.group_id == g.group_id)
                    .unwrap()
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

// Mock Group Repository
struct MockGroupRepository {
    group_store: Store<Group>,
    user_group_store: Store<UserGroup>,
}

impl MockGroupRepository {
    fn new(group_store: GroupStore, user_group_store: UserGroupStore) -> Self {
        Self {
            group_store,
            user_group_store,
        }
    }
}

#[async_trait]
impl keyrunes::repository::GroupRepository for MockGroupRepository {
    async fn find_by_name(&self, name: &str) -> Result<Option<Group>> {
        let groups = self.group_store.lock().unwrap();
        let group = groups.iter().cloned().find(|g| g.name == name);
        Ok(group)
    }

    async fn find_by_id(&self, group_id: i64) -> Result<Option<Group>> {
        let groups = self.group_store.lock().unwrap();
        let group = groups.iter().cloned().find(|g| g.group_id == group_id);
        Ok(group)
    }

    async fn insert_group(&self, new_group: keyrunes::repository::NewGroup) -> Result<Group> {
        let mut groups = self.group_store.lock().unwrap();
        let group = Group {
            group_id: groups.len() as i64,
            external_id: new_group.external_id,
            name: new_group.name,
            description: new_group.description,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        groups.push(group.clone());
        Ok(group)
    }

    async fn list_groups(&self) -> Result<Vec<Group>> {
        Ok(self.group_store.lock().unwrap().clone())
    }

    async fn assign_user_to_group(
        &self,
        user_id: i64,
        group_id: i64,
        assigned_by: Option<i64>,
    ) -> Result<()> {
        let mut user_groups = self.user_group_store.lock().unwrap();
        user_groups.push(UserGroup {
            user_id,
            group_id,
            assigned_by,
            assigned_at: Utc::now(),
        });
        Ok(())
    }

    async fn remove_user_from_group(&self, user_id: i64, group_id: i64) -> Result<()> {
        let mut user_groups = self.user_group_store.lock().unwrap();
        user_groups.retain(|g| !(g.user_id == user_id && g.group_id == group_id));
        Ok(())
    }

    async fn get_group_policies(&self, _group_id: i64) -> Result<Vec<Policy>> {
        Ok(Vec::new())
    }
}

// Mock Password Reset Repository
struct MockPasswordResetRepository;

#[async_trait]
impl keyrunes::repository::PasswordResetRepository for MockPasswordResetRepository {
    async fn create_reset_token(
        &self,
        _token: keyrunes::repository::NewPasswordResetToken,
    ) -> Result<keyrunes::repository::PasswordResetToken> {
        unimplemented!()
    }

    async fn find_valid_token(
        &self,
        _token: &str,
    ) -> Result<Option<keyrunes::repository::PasswordResetToken>> {
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
async fn test_register_and_login() {
    // Setup repositories
    let (group_store, user_groups_store) = create_stores();
    let user_repo = Arc::new(MockRepo::new(
        Arc::clone(&group_store),
        Arc::clone(&user_groups_store),
    ));
    let group_repo = Arc::new(MockGroupRepository::new(
        Arc::clone(&group_store),
        Arc::clone(&user_groups_store),
    ));
    let password_reset_repo = Arc::new(MockPasswordResetRepository);
    let jwt_service = Arc::new(keyrunes::services::jwt_service::JwtService::new(
        "test_secret",
    ));

    // Create service
    let service = UserService::new(
        user_repo.clone(),
        group_repo,
        password_reset_repo,
        jwt_service,
    );

    // Create registration request
    let req = RegisterRequest {
        email: "john@example.com".to_string(),
        username: "johndoe".to_string(),
        password: "Password123".to_string(),
        first_login: Some(false), // Added missing field
    };

    // Test registration
    let auth_response = service.register(req.clone()).await.unwrap();
    assert_eq!(auth_response.user.email, "john@example.com");
    assert_eq!(auth_response.user.username, "johndoe");
    assert!(!auth_response.token.is_empty());

    // Test login with email
    let login_response = service
        .login("john@example.com".to_string(), "Password123".to_string())
        .await
        .unwrap();
    assert_eq!(login_response.user.username, "johndoe");
    assert!(!login_response.token.is_empty());

    // Test login with username
    let login_response2 = service
        .login("johndoe".to_string(), "Password123".to_string())
        .await
        .unwrap();
    assert_eq!(login_response2.user.email, "john@example.com");

    // Test login with wrong password
    let err = service
        .login("johndoe".to_string(), "wrongpass".to_string())
        .await
        .unwrap_err();
    assert_eq!(err.to_string(), "invalid credentials");
}

#[tokio::test]
async fn test_duplicate_registration() {
    let (group_store, user_groups_store) = create_stores();
    let user_repo = Arc::new(MockRepo::new(
        Arc::clone(&group_store),
        Arc::clone(&user_groups_store),
    ));
    let group_repo = Arc::new(MockGroupRepository::new(
        Arc::clone(&group_store),
        Arc::clone(&user_groups_store),
    ));
    let password_reset_repo = Arc::new(MockPasswordResetRepository);
    let jwt_service = Arc::new(keyrunes::services::jwt_service::JwtService::new(
        "test_secret",
    ));

    let service = UserService::new(
        user_repo.clone(),
        group_repo,
        password_reset_repo,
        jwt_service,
    );

    let req = RegisterRequest {
        email: "duplicate@example.com".to_string(),
        username: "duplicateuser".to_string(),
        password: "Password123".to_string(),
        first_login: Some(false),
    };

    // First registration should succeed
    service.register(req.clone()).await.unwrap();

    // Second registration with same email should fail
    let result = service.register(req).await;
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("email already registered")
    );
}

#[tokio::test]
async fn test_password_validation() {
    let (group_store, user_groups_store) = create_stores();
    let user_repo = Arc::new(MockRepo::new(
        Arc::clone(&group_store),
        Arc::clone(&user_groups_store),
    ));
    let group_repo = Arc::new(MockGroupRepository::new(
        Arc::clone(&group_store),
        Arc::clone(&user_groups_store),
    ));
    let password_reset_repo = Arc::new(MockPasswordResetRepository);
    let jwt_service = Arc::new(keyrunes::services::jwt_service::JwtService::new(
        "test_secret",
    ));

    let service = UserService::new(user_repo, group_repo, password_reset_repo, jwt_service);

    // Test password too short
    let req = RegisterRequest {
        email: "short@example.com".to_string(),
        username: "shortpass".to_string(),
        password: "short".to_string(), // Too short
        first_login: Some(false),
    };

    let result = service.register(req).await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().to_string(), "password too short");
}

#[tokio::test]
async fn test_email_validation() {
    let (group_store, user_groups_store) = create_stores();
    let user_repo = Arc::new(MockRepo::new(
        Arc::clone(&group_store),
        Arc::clone(&user_groups_store),
    ));
    let group_repo = Arc::new(MockGroupRepository::new(
        Arc::clone(&group_store),
        Arc::clone(&user_groups_store),
    ));
    let password_reset_repo = Arc::new(MockPasswordResetRepository);
    let jwt_service = Arc::new(keyrunes::services::jwt_service::JwtService::new(
        "test_secret",
    ));

    let service = UserService::new(user_repo, group_repo, password_reset_repo, jwt_service);

    // Test invalid email
    let req = RegisterRequest {
        email: "invalid-email".to_string(), // Invalid email format
        username: "testuser".to_string(),
        password: "Password123".to_string(),
        first_login: Some(false),
    };

    let result = service.register(req).await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().to_string(), "invalid email");
}

#[tokio::test]
async fn test_change_password() {
    let (group_store, user_groups_store) = create_stores();
    let user_repo = Arc::new(MockRepo::new(
        Arc::clone(&group_store),
        Arc::clone(&user_groups_store),
    ));
    let group_repo = Arc::new(MockGroupRepository::new(
        Arc::clone(&group_store),
        Arc::clone(&user_groups_store),
    ));
    let password_reset_repo = Arc::new(MockPasswordResetRepository);
    let jwt_service = Arc::new(keyrunes::services::jwt_service::JwtService::new(
        "test_secret",
    ));

    let service = UserService::new(
        user_repo.clone(),
        group_repo,
        password_reset_repo,
        jwt_service,
    );

    // Register a user
    let req = RegisterRequest {
        email: "change@example.com".to_string(),
        username: "changeuser".to_string(),
        password: "OldPassword123".to_string(),
        first_login: Some(true),
    };

    let auth_response = service.register(req).await.unwrap();
    let user_id = auth_response.user.user_id;

    // Change password
    let change_req = keyrunes::services::user_service::ChangePasswordRequest {
        current_password: "OldPassword123".to_string(),
        new_password: "NewPassword456".to_string(),
    };

    service.change_password(user_id, change_req).await.unwrap();

    // Verify login with new password
    let login_result = service
        .login(
            "change@example.com".to_string(),
            "NewPassword456".to_string(),
        )
        .await;
    assert!(login_result.is_ok());

    // Verify login with old password fails
    let old_login_result = service
        .login(
            "change@example.com".to_string(),
            "OldPassword123".to_string(),
        )
        .await;
    assert!(old_login_result.is_err());
}

#[tokio::test]
async fn admin_create_user_with_groups() {
    let (group_store, user_groups_store) = create_stores();
    let user_repo = Arc::new(MockRepo::new(
        Arc::clone(&group_store),
        Arc::clone(&user_groups_store),
    ));
    let group_repo = Arc::new(MockGroupRepository::new(
        Arc::clone(&group_store),
        Arc::clone(&user_groups_store),
    ));
    let password_reset_repo = Arc::new(MockPasswordResetRepository);
    let jwt_service = Arc::new(keyrunes::services::jwt_service::JwtService::new(
        "test_secret",
    ));

    let service = UserService::new(
        user_repo.clone(),
        group_repo.clone(),
        password_reset_repo,
        jwt_service,
    );

    let group_service = GroupService::new(group_repo);

    // Register superadmin
    let superadmin = service
        .create_user(
            CreateUserRequest {
                email: Email::try_from("admin@example.com").unwrap(),
                username: "admin".to_string(),
                password: Password::try_from("Password123").unwrap(),
                // Assign to 'superadmin' group by default
                groups: Some(vec!["superadmin".to_string()]),
                first_login: false,
            },
            None,
        )
        .await
        .unwrap();

    // create group
    let test_group = group_service
        .create_group(CreateGroupRequest {
            name: "test".to_string(),
            description: Some("Test Group".to_string()),
        })
        .await
        .unwrap();

    // Assert - group is now 3
    assert_eq!(group_store.lock().unwrap().len(), 3);

    // create user with test group
    let test_user = service
        .create_user(
            CreateUserRequest {
                email: Email::try_from("testuser@example.com").unwrap(),
                username: "testuser".to_string(),
                password: Password::try_from("Password123").unwrap(),
                groups: Some(vec!["users".to_string(), test_group.name]),
                first_login: false,
            },
            Some(superadmin.user_id),
        )
        .await;
    assert!(test_user.is_ok());
    let test_user = test_user.unwrap();

    assert_eq!(test_user.email, "testuser@example.com");
    assert_eq!(test_user.username, "testuser");
    assert_eq!(test_user.groups, &["users", "test"]);

    // create user with invalid group
    let test_user = service
        .create_user(
            CreateUserRequest {
                email: Email::try_from("testuser2@example.com").unwrap(),
                username: "testuser2".to_string(),
                password: Password::try_from("Password123").unwrap(),
                groups: Some(vec!["users".to_string(), "invalid".to_string()]),
                first_login: false,
            },
            Some(superadmin.user_id),
        )
        .await;
    assert!(test_user.is_err());
    assert_eq!(
        test_user.err().unwrap().to_string(),
        "invalid group specified: `invalid`"
    )
}
