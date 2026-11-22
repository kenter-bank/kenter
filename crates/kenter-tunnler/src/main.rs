mod auth;
mod config;
mod dispatch;
mod error;
mod proxy;
mod roster;
mod server;
mod state;
mod ws;

#[cfg(test)]
mod local_tunnel_test;
#[cfg(test)]
mod multi_node_test;

use std::sync::Arc;

use kenter_crypto::keypair::StellarKeypair;
use tracing::info;

use crate::config::AppConfig;
use crate::state::AppState;

#[tokio::main]
async fn main() {
    // Load .env file (optional, silently ignored if missing)
    let _ = dotenvy::dotenv();

    // Load configuration
    let config = AppConfig::from_env().unwrap_or_else(|e| {
        eprintln!("Configuration error: {e}");
        std::process::exit(1);
    });

    // Initialize tracing
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&config.log_level));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    // Create server keypair from secret
    let server_keypair = StellarKeypair::from_stellar_secret(&config.server_secret)
        .unwrap_or_else(|e| {
            eprintln!("Invalid TUNNLER_SERVER_SECRET: {e}");
            std::process::exit(1);
        });

    let server_address = server_keypair.stellar_address();
    let bind_addr = config.bind_addr();

    info!(
        %server_address,
        domain = %config.domain,
        %bind_addr,
        "kenter-tunnler starting"
    );

    // Initialize roster cache (if contract ID is configured)
    let roster = if let Some(ref contract_id) = config.roster_contract_id {
        match roster::RosterCache::new(
            &config.soroban_rpc_url,
            contract_id,
            config.roster_cache_ttl,
        ) {
            Ok(r) => {
                // Name the roster explicitly. This value comes from the
                // environment (often a .env the operator forgot about), so it
                // drifts whenever the roster contract is redeployed — and the
                // symptom is a node that registered successfully being told
                // "not on roster" at auth, which points nowhere near the cause.
                info!(
                    roster = %contract_id,
                    rpc = %config.soroban_rpc_url,
                    "roster gating ENABLED — only nodes on this roster may connect"
                );
                Some(r)
            }
            Err(e) => {
                eprintln!("Failed to initialize roster cache: {e}");
                std::process::exit(1);
            }
        }
    } else {
        info!("roster gating disabled (no ROSTER_CONTRACT_ID)");
        None
    };

    // Build state
    let state = Arc::new(AppState::new(config, server_keypair, roster));

    // Spawn cleanup task for expired challenges, roster cache, and stale sessions
    let session_timeout = std::time::Duration::from_secs(state.config.session_timeout);
    let cleanup_state = Arc::clone(&state);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            cleanup_state.challenges.cleanup();
            if let Some(ref roster) = cleanup_state.roster {
                roster.cleanup();
            }
            let expired = cleanup_state.connections.expire_sessions(session_timeout);
            if expired > 0 {
                info!(expired, "expired stale sessions");
            }
        }
    });

    // Build router
    let app = server::build_router(state);

    // Start server
    let listener = tokio::net::TcpListener::bind(bind_addr)
        .await
        .unwrap_or_else(|e| {
            eprintln!("Failed to bind {bind_addr}: {e}");
            std::process::exit(1);
        });

    info!(%bind_addr, "listening");

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .unwrap_or_else(|e| {
        eprintln!("Server error: {e}");
        std::process::exit(1);
    });

    info!("shutdown complete");
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("failed to install ctrl+c handler");
    info!("shutdown signal received");
}
