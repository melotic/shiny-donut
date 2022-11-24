use std::sync::Arc;

use crate::cli::{DeviceOption, Security};
use crate::{capture, cli, SHINY_DONUT_LOGO};
use actix_files::NamedFile;
use actix_web::{
    dev::ServiceRequest,
    error, get, middleware,
    web::{self, Data},
    App, Error, HttpResponse, HttpServer, Responder,
};
use actix_web_httpauth::{extractors::basic::BasicAuth, middleware::HttpAuthentication};
use color_eyre::{eyre::Context, Help, Result};
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};
use tracing::info;

async fn traffic(data: Data<Arc<DeviceOption>>) -> actix_web::Result<impl Responder> {
    // send pcap from capture
    Ok(NamedFile::open_async(capture::get_pcap_path(&data.interface)).await?)
}

#[get("/")]
async fn index() -> impl Responder {
    let html = include_str!("../static/index.html").replace("{version}", env!("CARGO_PKG_VERSION"));
    HttpResponse::Ok().content_type("text/html").body(html)
}

async fn validator(
    req: ServiceRequest,
    credentials: BasicAuth,
) -> Result<ServiceRequest, (Error, ServiceRequest)> {
    let data = req.app_data::<Data<Arc<cli::Security>>>();

    let data = match data {
        Some(data) => data,
        None => return Err((error::ErrorInternalServerError("No security app data"), req)),
    };

    if data.password == credentials.user_id() {
        Ok(req)
    } else {
        Err((error::ErrorUnauthorized("Invalid credentials"), req))
    }
}

pub async fn server(port: u16, device: DeviceOption, security: Security) -> Result<()> {
    println!("{}", SHINY_DONUT_LOGO);
    let device = Arc::new(device);
    let security = Arc::new(security);

    let stream = capture::start_capture(&device.interface, port)?;
    tokio::spawn(capture::packet_listener(stream));

    info!("Configuring HTTPS certificates");

    let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls())?;
    builder
        .set_private_key_file("key.pem", SslFiletype::PEM)
        .with_context(|| "Failed to open `key.pem`")
        .with_suggestion(|| "generate a self-signed certificate with `openssl req -x509 -newkey rsa:4096 -nodes -keyout key.pem -out cert.pem -days 365`")?;
    builder.set_certificate_chain_file("cert.pem")?;

    info!("Starting shiny-donut server on port {}", port);

    // Create an HTTPs server
    HttpServer::new(move || {
        App::new()
            .wrap(middleware::Logger::default())
            .wrap(middleware::Compress::default())
            .service(index)
            .app_data(Data::new(security.clone()))
            .app_data(Data::new(device.clone()))
            .service(
                web::resource("/traffic")
                    .route(web::get().to(traffic))
                    .wrap(HttpAuthentication::basic(validator)),
            )
    })
    .bind_openssl(("0.0.0.0", port), builder)?
    .run()
    .await?;

    Ok(())
}
