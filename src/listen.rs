use std::{path::PathBuf, sync::Arc};

use actix_web::{
    error, get, middleware,
    web::{self, Data, PayloadConfig},
    App, HttpRequest, HttpResponse, HttpServer, Responder,
};
use actix_web_httpauth::middleware::HttpAuthentication;
use color_eyre::{eyre::Context, Help, Result};
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};
use tracing::info;

use crate::{auth, cli::Security};

#[get("/")]
async fn index() -> impl Responder {
    let html = include_str!("../static/index.html").replace("{version}", env!("CARGO_PKG_VERSION"));
    HttpResponse::Ok().content_type("text/html").body(html)
}

async fn traffic(req: HttpRequest, pcap: web::Bytes) -> actix_web::Result<impl Responder> {
    let peer_addr = req
        .peer_addr()
        .ok_or_else(|| error::ErrorInternalServerError("Couldnt get ip addr"))?;

    info!("Got traffic from {}", peer_addr);

    // Create data dir if not existing
    let data_dir = PathBuf::from("data");
    if !data_dir.exists() {
        std::fs::create_dir(&data_dir)?;
    }

    // Save to pcap file, data/{ip}.pcap
    let path = data_dir.join(format!("{}.pcap", peer_addr.ip()));
    tokio::fs::write(path, pcap).await?;

    Ok(HttpResponse::Ok())
}

pub async fn listen(address: String, port: u16, security: Security) -> Result<()> {
    info!("Configuring HTTPS certificates");

    let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls())?;
    builder
        .set_private_key_file("key.pem", SslFiletype::PEM)
        .with_context(|| "Failed to open `key.pem`")
        .with_suggestion(|| "generate a self-signed certificate with `openssl req -x509 -newkey rsa:4096 -nodes -keyout key.pem -out cert.pem -days 365`")?;
    builder.set_certificate_chain_file("cert.pem")?;

    info!("Starting shiny-donut server on port {}", port);

    let security = Arc::new(security);

    // Create an HTTPs server
    HttpServer::new(move || {
        App::new()
            .wrap(middleware::Logger::default())
            .wrap(middleware::Compress::default())
            .service(index)
            .app_data(Data::new(security.clone()))
            .service(
                web::resource("/traffic")
                    .route(web::post().to(traffic))
                    .wrap(HttpAuthentication::basic(auth::validator))
                    .app_data(PayloadConfig::new(usize::MAX)),
            )
    })
    .bind_openssl((address, port), builder)?
    .run()
    .await?;

    Ok(())
}
