use keyrunes::repository::sqlx_impl::PgUserRepository;
use keyrunes::repository::{NewUser, UserRepository};
use sqlx::{PgPool, migrate::Migrator};
use std::env;
use url::Url;
use uuid::Uuid;

static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

// Setup test database
async fn setup_test_db() -> (PgPool, String) {
    let admin_url = env::var("TEST_DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:password@localhost:5432/postgres".to_string());

    let admin_pool = PgPool::connect(&admin_url).await.unwrap();

    let db_name = format!("test_db_{}", Uuid::new_v4().to_string().replace("-", "_"));
    sqlx::query(&format!(r#"CREATE DATABASE "{}""#, db_name))
        .execute(&admin_pool)
        .await
        .unwrap();

    let mut url = Url::parse(&admin_url).unwrap();
    url.set_path(&db_name);
    let test_db_url = url.as_str().to_string();

    let pool = PgPool::connect(&test_db_url).await.unwrap();

    // Run migrations
    MIGRATOR.run(&pool).await.unwrap();

    (pool, db_name)
}

async fn teardown_test_db(db_name: String) {
    let admin_url = env::var("TEST_DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:password@localhost:5432/postgres".to_string());
    let admin_pool = PgPool::connect(&admin_url).await.unwrap();

    // Revoke connections
    sqlx::query(&format!(
        "REVOKE CONNECT ON DATABASE \"{}\" FROM PUBLIC;",
        db_name
    ))
    .execute(&admin_pool)
    .await
    .unwrap();

    // Terminate existing connections
    sqlx::query(&format!(
        "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='{}';",
        db_name
    ))
    .execute(&admin_pool)
    .await
    .unwrap();

    // Drop database
    sqlx::query(&format!("DROP DATABASE \"{}\";", db_name))
        .execute(&admin_pool)
        .await
        .unwrap();
}

#[tokio::test]
#[ignore]
async fn test_insert_and_find_user() {
    // Setup
    let (pool, db_name) = setup_test_db().await;
    let repo = PgUserRepository::new(pool.clone());

    let new_user = NewUser {
        external_id: Uuid::new_v4(),
        email: "john@test.com".to_string(),
        username: "johndoe".to_string(),
        password_hash: "hashed_password".to_string(),
        first_login: false, // Added missing field
    };

    // Act - Insert user
    let user = repo.insert_user(new_user.clone()).await.unwrap();

    // Assert - Check inserted user
    assert_eq!(user.email, new_user.email);
    assert_eq!(user.username, new_user.username);
    assert_eq!(user.first_login, new_user.first_login);

    // Test find by email
    let found_by_email = repo.find_by_email("john@test.com").await.unwrap().unwrap();
    assert_eq!(found_by_email.email, new_user.email);
    assert_eq!(found_by_email.username, new_user.username);

    // Test find by username
    let found_by_username = repo.find_by_username("johndoe").await.unwrap().unwrap();
    assert_eq!(found_by_username.email, new_user.email);
    assert_eq!(found_by_username.username, new_user.username);

    // Test find by id
    let found_by_id = repo.find_by_id(user.user_id).await.unwrap().unwrap();
    assert_eq!(found_by_id.email, new_user.email);
    assert_eq!(found_by_id.username, new_user.username);

    // Cleanup
    teardown_test_db(db_name).await;
}

#[tokio::test]
#[ignore]
async fn test_update_user_password() {
    let (pool, db_name) = setup_test_db().await;
    let repo = PgUserRepository::new(pool.clone());

    // Insert a user
    let new_user = NewUser {
        external_id: Uuid::new_v4(),
        email: "password@test.com".to_string(),
        username: "passworduser".to_string(),
        password_hash: "old_hash".to_string(),
        first_login: true,
    };

    let user = repo.insert_user(new_user).await.unwrap();

    // Update password
    repo.update_user_password(user.user_id, "new_hash")
        .await
        .unwrap();

    // Verify password was updated
    let updated_user = repo.find_by_id(user.user_id).await.unwrap().unwrap();
    assert_eq!(updated_user.password_hash, "new_hash");

    teardown_test_db(db_name).await;
}

#[tokio::test]
#[ignore]
async fn test_set_first_login() {
    let (pool, db_name) = setup_test_db().await;
    let repo = PgUserRepository::new(pool.clone());

    // Insert a user with first_login = true
    let new_user = NewUser {
        external_id: Uuid::new_v4(),
        email: "firstlogin@test.com".to_string(),
        username: "firstloginuser".to_string(),
        password_hash: "hash".to_string(),
        first_login: true,
    };

    let user = repo.insert_user(new_user).await.unwrap();
    assert!(user.first_login);

    // Set first_login to false
    repo.set_first_login(user.user_id, false).await.unwrap();

    // Verify first_login was updated
    let updated_user = repo.find_by_id(user.user_id).await.unwrap().unwrap();
    assert!(!updated_user.first_login);

    teardown_test_db(db_name).await;
}

#[tokio::test]
#[ignore]
async fn test_duplicate_email() {
    let (pool, db_name) = setup_test_db().await;
    let repo = PgUserRepository::new(pool.clone());

    let new_user = NewUser {
        external_id: Uuid::new_v4(),
        email: "duplicate@test.com".to_string(),
        username: "user1".to_string(),
        password_hash: "hash".to_string(),
        first_login: false,
    };

    // First insert should succeed
    repo.insert_user(new_user.clone()).await.unwrap();

    // Second insert with same email but different username should fail
    let duplicate_user = NewUser {
        external_id: Uuid::new_v4(),
        email: "duplicate@test.com".to_string(),
        username: "user2".to_string(),
        password_hash: "hash".to_string(),
        first_login: false,
    };

    let result = repo.insert_user(duplicate_user).await;
    assert!(result.is_err());

    teardown_test_db(db_name).await;
}

#[tokio::test]
#[ignore]
async fn test_duplicate_username() {
    let (pool, db_name) = setup_test_db().await;
    let repo = PgUserRepository::new(pool.clone());

    let new_user = NewUser {
        external_id: Uuid::new_v4(),
        email: "user1@test.com".to_string(),
        username: "duplicateusername".to_string(),
        password_hash: "hash".to_string(),
        first_login: false,
    };

    // First insert should succeed
    repo.insert_user(new_user.clone()).await.unwrap();

    // Second insert with same username but different email should fail
    let duplicate_user = NewUser {
        external_id: Uuid::new_v4(),
        email: "user2@test.com".to_string(),
        username: "duplicateusername".to_string(),
        password_hash: "hash".to_string(),
        first_login: false,
    };

    let result = repo.insert_user(duplicate_user).await;
    assert!(result.is_err());

    teardown_test_db(db_name).await;
}

#[tokio::test]
#[ignore]
async fn test_case_insensitive_email() {
    let (pool, db_name) = setup_test_db().await;
    let repo = PgUserRepository::new(pool.clone());

    let new_user = NewUser {
        external_id: Uuid::new_v4(),
        email: "CaseTest@Test.com".to_string(),
        username: "caseuser".to_string(),
        password_hash: "hash".to_string(),
        first_login: false,
    };

    repo.insert_user(new_user.clone()).await.unwrap();

    // Should find user with different case email
    let found = repo.find_by_email("casetest@test.com").await.unwrap();
    assert!(found.is_some());
    assert_eq!(found.unwrap().username, "caseuser");

    teardown_test_db(db_name).await;
}
