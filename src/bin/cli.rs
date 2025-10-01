use clap::{Parser, Subcommand};
use keyrunes::jwt_service::JwtService;
use keyrunes::repository::sqlx_impl::PgUserRepository;
use keyrunes::services::user_service::{RegisterRequest, UserService};
use keyrunes::sqlx_impl::{PgGroupRepository, PgPasswordResetRepository};
use sqlx::PgPool;
use std::sync::Arc;

#[derive(Parser)]
#[clap(name = "Keyrunes CLI")]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
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
    Login {
        #[clap(long)]
        identity: String, // email ou username
        #[clap(long)]
        password: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
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
    }

    Ok(())
}
