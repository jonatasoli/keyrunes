use clap::{Parser, Subcommand};
use keyrunes::repository::sqlx_impl::PgUserRepository;
use keyrunes::services::user_service::{RegisterRequest, UserService};
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
    let cli = Cli::parse();

    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:password@localhost:5432/postgres".into());

    let pool = PgPool::connect(&database_url).await?;
    let repo = PgUserRepository::new(pool);
    let service = Arc::new(UserService::new(Arc::new(repo)));

    match cli.command {
        Commands::Register {
            email,
            username,
            password,
        } => {
            let req = RegisterRequest {
                email,
                username,
                password,
            };
            match service.register(req).await {
                Ok(u) => println!("Created user {} (external_id={})", u.user_id, u.external_id),
                Err(e) => eprintln!("Error registering user: {}", e),
            }
        }
        Commands::Login { identity, password } => match service.login(identity, password).await {
            Ok(u) => println!("Login successful! Welcome {}", u.username),
            Err(e) => eprintln!("Login failed: {}", e),
        },
    }

    Ok(())
}
