use clap::{Parser, Subcommand};
use keyrunes::jwt_service::JwtService;
use keyrunes::repository::sqlx_impl::PgUserRepository;
use keyrunes::services::user_service::{RegisterRequest, UserService};
use keyrunes::sqlx_impl::{PgGroupRepository, PgPasswordResetRepository};
use keyrunes::user_service::AdminChangePasswordRequest;
use sqlx::PgPool;
use std::sync::Arc;

#[derive(Parser)]
#[clap(name = "Keyrunes CLI")]
#[clap(about = "Use keyrunes via cli as sysadmin, or developer")]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Register User with username, password and email
    Register {
        #[clap(long)]
        email: String,
        #[clap(long)]
        username: String,
        #[clap(long)]
        password: String,
        #[clap(long)]
        first_login: bool,
    },
    /// Login as a user with username, password
    Login {
        // identity can be username or email
        #[clap(long)]
        identity: String, // email ou username
        #[clap(long)]
        password: String,
    },
    /// recover user by generating token
    Recover_User {
        #[clap(long)]
        username: String,
        #[clap(long)]
        generate_token: bool,
    },
    /// set user password
    Set_User_Password {
        #[clap(long)]
        email: String,

        #[clap(long)]
        set_password: bool,

        #[clap(long)]
        password: String
    }

}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();

    // Initialize tracing
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:password@localhost:5432/postgres".into());

    let pool = PgPool::connect(&database_url).await?;
    let user_repo = Arc::new(PgUserRepository::new(pool.clone()));
    let group_repo = Arc::new(PgGroupRepository::new(pool.clone()));
    let password_reset_repo = Arc::new(PgPasswordResetRepository::new(pool.clone()));
    let jwt_secret = std::env::var("JWT_SECRET")
        .unwrap_or_else(|_| "your-super-secret-jwt-key-change-in-production".into());
    let jwt_service = Arc::new(JwtService::new(&jwt_secret));
    let service = Arc::new(UserService::new(
        user_repo,
        group_repo,
        password_reset_repo,
        jwt_service.clone(),
    ));

    match cli.command {
        Commands::Register {
            email,
            username,
            password,
            first_login,
        } => {
            let req = RegisterRequest {
                email,
                username,
                password,
                first_login: Some(first_login),
            };
            match service.register(req).await {
                Ok(u) => println!(
                    "Created user {} (external_id={})",
                    u.user.user_id, u.user.external_id
                ),
                Err(e) => eprintln!("Error registering user: {}", e),
            }
        }
        Commands::Login { identity, password } => match service.login(identity, password).await {
            Ok(u) => println!("Login successful! Welcome {}", u.user.username),
            Err(e) => eprintln!("Login failed: {}", e),
        },
        Commands::Recover_User {
            username,
            generate_token,
        } => {
            // find user by username
            let res = service.find_user_by_username(&username).await;

            if res.is_none(){
                return Err(anyhow::anyhow!("User {} not found", &username));
            }

            let user = res.unwrap();

            let user_group = service.get_user_group_names(user.user_id).await?;

            let token  = jwt_service.generate_token(
                user.user_id,
                user.username.as_str(),
                user.email.as_str(),
                user_group
            ).map_err(|err| {
                tracing::error!("Error generating token: {}", err);
            });

            tracing::info!("Generated reset url for user {} below", username);
            tracing::info!("reset url http://127.0.0.1:3000?token={}", token.unwrap())

        },
        Commands::Set_User_Password {
            email,
            set_password: _set_password,
            password
        } => {

            let user = service.find_user_by_email(&email).await;

            if user.is_none() {
                return Err(anyhow::anyhow!("User with email {} not found", &email));
            }

            let user = user.unwrap();
            let change_password_request = AdminChangePasswordRequest{ 
                user_id: user.user_id,
                new_password: password.to_string() 
            };

            service.update_password(change_password_request).await?;
            
            tracing::info!("Updated password successfully for {}", user.username);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::process::Command;
    // populate the database with the user details below before running tests.
    // make sure you have run cargo build

    const USERNAME: &str = "test";
    const EMAIL: &str = "test@gmail.com";
    const PASSWORD: &str = "password";

   #[test]
    fn test_admin_changes_user_password_successfully() {

       let output = Command::new("./target/debug/cli")
           .args(&[
               "set-user-password",
               "--email",
               EMAIL,
               "--password",
                PASSWORD,
           ])
           .output()
           .expect("Failed to execute command");

       assert!(output.status.success());

        let stdout = String::from_utf8(output.stdout).unwrap();

        assert!(stdout.contains("Updated password successfully"));
    }

    #[test]
    fn test_admin_changes_user_password_unsuccessfully() {

       let output = Command::new("./target/debug/cli")
           .args(&[
               "set-user-password",
               "--email",
               &EMAIL[9..],
               "--password",
                PASSWORD,
           ])
           .output()
           .expect("Failed to execute command");

       assert!(!output.status.success());

        let stderr = String::from_utf8(output.stderr).unwrap();

        let err = &EMAIL[9..];

        assert!(stderr.contains(format!("Error: User with email {} not found", err).as_str()));
    }


    #[test]
    fn test_recover_user_with_url_successfully() {

        let output = Command::new("./target/debug/cli")
            .args(&[
                "recover-user",
                "--username",
                &USERNAME,
                "--generate-token",
            ])
            .output()
            .expect("Failed to execute command");

        assert!(output.status.success());

        let stdout = String::from_utf8(output.stdout).unwrap();

        assert!(stdout.contains("http://127.0.0.1:3000?token=e"));
    }


    #[test]
    fn test_recover_user_with_url_unsuccessfully() {

       let output = Command::new("./target/debug/cli")
           .args(&[
               "recover-user",
               "--username",
               &USERNAME[3..],
               "--generate-token",
           ])
           .output()
           .expect("Failed to execute command");

       assert!(!output.status.success());

        let stderr = String::from_utf8(output.stderr).unwrap();

        let err = &USERNAME[3..];

        assert!(stderr.contains(format!("Error: User {} not found", err).as_str()));
    }

}
