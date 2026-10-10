use std::net::SocketAddr;

use cachette::routes;
use cachette::state::AppState;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Hardcoded default until config loading lands in plan task 5.
    let addr = SocketAddr::from(([127, 0, 0, 1], 8080));
    let app = routes::router(AppState::new());
    let listener = tokio::net::TcpListener::bind(addr).await?;
    println!("cachette listening on http://{addr}");
    axum::serve(listener, app).await?;
    Ok(())
}
