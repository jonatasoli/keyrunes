use keyrunes::repository::sqlx_impl::PgUserRepository;
use keyrunes::repository::{NewUser, UserRepository};
use sqlx::{PgPool, migrate::Migrator};
use std::env;
use url::Url;
use uuid::Uuid;

static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

//Setup database
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

    MIGRATOR.run(&pool).await.unwrap();

    (pool, db_name)
}

async fn teardown_test_db(db_name: String) {
    let admin_url = env::var("TEST_DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:password@localhost:5432/postgres".to_string());
    let admin_pool = PgPool::connect(&admin_url).await.unwrap();

    sqlx::query(&format!(
        "REVOKE CONNECT ON DATABASE \"{}\" FROM PUBLIC;",
        db_name
    ))
    .execute(&admin_pool)
    .await
    .unwrap();
    sqlx::query(&format!(
        "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='{}';",
        db_name
    ))
    .execute(&admin_pool)
    .await
    .unwrap();
    sqlx::query(&format!("DROP DATABASE \"{}\";", db_name))
        .execute(&admin_pool)
        .await
        .unwrap();
}

#[tokio::test]
async fn test_insert_and_find_user() {
    // Setup
    let (pool, db_name) = setup_test_db().await;
    let repo = PgUserRepository::new(pool.clone());

    let new_user = NewUser {
        external_id: Uuid::new_v4(),
        email: "john@test.com".to_string(),
        username: "johndoe".to_string(),
        password_hash: "hashed_password".to_string(),
    };

    // Act
    let user = repo.insert_user(new_user.clone()).await.unwrap();

    // Assert
    assert_eq!(user.email, new_user.email);
    assert_eq!(user.username, new_user.username);

    let found_by_email = repo.find_by_email("john@test.com").await.unwrap().unwrap();
    assert_eq!(found_by_email.email, new_user.email);
    assert_eq!(found_by_email.username, new_user.username);

    let found_by_username = repo.find_by_username("johndoe").await.unwrap().unwrap();
    assert_eq!(found_by_username.email, new_user.email);
    assert_eq!(found_by_username.username, new_user.username);

    teardown_test_db(db_name).await;
}
