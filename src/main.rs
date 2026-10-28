//! `simplifi-mcp` CLI — client-library commands plus the MCP server transports
//! (`serve` = stdio, `serve-http` = feature-gated Streamable HTTP). Credentials come
//! only from the environment (`op run` pattern): SIMPLIFI_EMAIL, SIMPLIFI_PASSWORD,
//! SIMPLIFI_CLIENT_SECRET.

use std::io::Write;

use clap::{Parser, Subcommand};

use simplifi_mcp::{
    Config, Credentials, ListTransactionsParams, LoginFlow, SimplifiClient,
};

#[derive(Parser)]
#[command(
    name = "simplifi-mcp",
    version,
    about = "Unofficial Quicken Simplifi client (internal web API — use at your own risk)"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Interactive credential login (prompts on stdin for an MFA code if challenged).
    Login,
    /// Seed the token cache from a web-app session export (the value of
    /// localStorage["authSession"] from a signed-in browser), for users who
    /// cannot hand their password to the CLI. Delete the export file after.
    ImportSession {
        /// Path to the authSession export (JSON).
        #[arg(long)]
        from_auth_session: std::path::PathBuf,
    },
    /// Clear cached Simplifi tokens.
    Logout,
    /// Show redacted token-cache status (never prints secrets).
    Status,
    /// GET /userprofiles/me token sanity probe.
    Whoami,
    /// List datasets visible to this user.
    Datasets,
    /// List accounts.
    Accounts,
    /// List transactions.
    Transactions {
        /// Per-page limit (default 50 for display; server max observed 5000).
        #[arg(long, default_value_t = 50)]
        limit: u32,
        /// Only transactions on/after this date (YYYY-MM-DD).
        #[arg(long)]
        date_on_after: Option<String>,
        /// Only transactions modified after this ISO datetime.
        #[arg(long)]
        modified_after: Option<String>,
        /// Follow nextLink pagination to the end.
        #[arg(long)]
        all: bool,
    },
    /// List categories (full pagination).
    Categories,
    /// List tags (full pagination).
    Tags,
    /// POST /transactions/earliest-date-on (all accounts unless ids given).
    EarliestDateOn {
        #[arg(long)]
        account_id: Vec<String>,
    },
    /// Dump the raw `split` object of one transaction plus its parsed lines —
    /// the inspection step for HAR-verifying the split write shape.
    InspectSplit {
        /// Transaction id.
        transaction_id: String,
        /// Bound the id scan to transactions on/after this date (YYYY-MM-DD).
        #[arg(long)]
        date_on_after: Option<String>,
    },
    /// Run the MCP server on stdio (for Claude Desktop / Claude Code / any MCP client).
    Serve,
    /// Run the MCP server over Streamable HTTP with mandatory bearer auth
    /// (requires SIMPLIFI_MCP_HTTP_TOKEN; loopback-only by default).
    #[cfg(feature = "http")]
    ServeHttp {
        /// Bind address (default 127.0.0.1:8787).
        #[arg(long)]
        bind: Option<String>,
    },
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    if let Err(e) = run().await {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

async fn run() -> simplifi_mcp::Result<()> {
    let cli = Cli::parse();
    let cfg = Config::from_env()?;
    let client = SimplifiClient::new(cfg)?;

    match cli.command {
        Command::Login => {
            let creds = client.config().credentials.as_ref().ok_or_else(|| {
                simplifi_mcp::Error::Config(
                    "SIMPLIFI_EMAIL / SIMPLIFI_PASSWORD not set — run via `op run` or export them"
                        .to_string(),
                )
            })?;
            // Borrow checker: clone the pieces we need before mutably using client.
            let creds = Credentials {
                username: creds.username.clone(),
                password: secrecy::SecretString::from(
                    secrecy::ExposeSecret::expose_secret(&creds.password).to_string(),
                ),
            };
            match client.auth().login(&creds).await? {
                LoginFlow::Complete => println!("login complete; tokens cached (encrypted)"),
                LoginFlow::MfaRequired(challenge) => {
                    let target = challenge
                        .email
                        .clone()
                        .or_else(|| challenge.phone.clone())
                        .unwrap_or_default();
                    eprint!(
                        "MFA code sent via {} {}: ",
                        challenge.mfa_channel, target
                    );
                    std::io::stderr().flush().ok();
                    let mut code = String::new();
                    std::io::stdin()
                        .read_line(&mut code)
                        .map_err(simplifi_mcp::Error::Io)?;
                    client
                        .auth()
                        .complete_mfa(&creds, &challenge, code.trim())
                        .await?;
                    println!("MFA login complete; tokens cached (encrypted)");
                }
            }
        }
        Command::ImportSession { from_auth_session } => {
            let text = std::fs::read_to_string(&from_auth_session)?;
            let tokens = simplifi_mcp::parse_auth_session_export(&text)?;
            client.auth().cache().store_tokens(&tokens)?;
            // Redacted confirmation only — never the token values.
            print_json(&client.auth().cache().status())?;
            eprintln!(
                "session imported; tokens cached (encrypted). \
                 Delete the export file now: {}",
                from_auth_session.display()
            );
        }
        Command::Logout => {
            client.auth().logout()?;
            println!("cached tokens cleared");
        }
        Command::Status => {
            print_json(&client.auth().cache().status())?;
        }
        Command::Whoami => {
            let me = client.whoami().await?;
            print_json(&me)?;
        }
        Command::Datasets => {
            let ds = client.list_datasets().await?;
            print_json(&ds)?;
        }
        Command::Accounts => {
            let accounts = client.list_accounts().await?;
            print_json(&accounts)?;
        }
        Command::Transactions {
            limit,
            date_on_after,
            modified_after,
            all,
        } => {
            let params = ListTransactionsParams {
                limit: Some(limit),
                date_on_after,
                modified_after,
                ..Default::default()
            };
            if all {
                let (txns, as_of) = client.list_transactions_all(&params).await?;
                eprintln!("{} transactions (asOf {:?})", txns.len(), as_of);
                print_json(&txns)?;
            } else {
                let page = client.list_transactions(&params).await?;
                print_json(&page)?;
            }
        }
        Command::Categories => {
            let cats = client.list_categories_all().await?;
            print_json(&cats)?;
        }
        Command::Tags => {
            let tags = client.list_tags_all().await?;
            print_json(&tags)?;
        }
        Command::EarliestDateOn { account_id } => {
            let r = client.earliest_date_on(&account_id).await?;
            print_json(&r)?;
        }
        Command::InspectSplit {
            transaction_id,
            date_on_after,
        } => {
            let txn = client
                .find_transaction(&transaction_id, date_on_after.as_deref())
                .await?
                .ok_or_else(|| {
                    simplifi_mcp::Error::Config(format!(
                        "transaction {transaction_id} not found"
                    ))
                })?;
            let lines: Vec<serde_json::Value> = txn
                .split_lines()
                .unwrap_or_default()
                .iter()
                .map(|l| {
                    serde_json::json!({
                        "categoryId": l.coa.as_ref().and_then(|c| c.id.clone()),
                        "amount": l.amount.map(|a| a.to_string()),
                        "memo": l.memo,
                    })
                })
                .collect();
            print_json(&serde_json::json!({
                "id": txn.id,
                "split": txn.split_raw().cloned().unwrap_or(serde_json::Value::Null),
                "parsedLines": lines,
            }))?;
        }
        Command::Serve => {
            use rmcp::ServiceExt;
            let server = simplifi_mcp::SimplifiMcpServer::new(client);
            tracing::info!("simplifi-mcp MCP server starting on stdio");
            let running = server
                .serve(rmcp::transport::stdio())
                .await
                .map_err(|e| simplifi_mcp::Error::Transport(format!("mcp serve: {e}")))?;
            running
                .waiting()
                .await
                .map_err(|e| simplifi_mcp::Error::Transport(format!("mcp wait: {e}")))?;
        }
        #[cfg(feature = "http")]
        Command::ServeHttp { bind } => {
            let server = simplifi_mcp::SimplifiMcpServer::new(client);
            simplifi_mcp::http::serve_http(server, bind).await?;
        }
    }
    Ok(())
}

fn print_json<T: serde::Serialize>(v: &T) -> simplifi_mcp::Result<()> {
    println!("{}", serde_json::to_string_pretty(v)?);
    Ok(())
}
