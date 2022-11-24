use color_eyre::Result;
use color_eyre::{eyre::Context, Help};
use reqwest::{Client, ClientBuilder};
use tokio::fs::File;
use tokio::time::{self, Duration};

use crate::capture;
use crate::cli::{DeviceOption, Security};

async fn test_connection(url: &str, client: &Client) -> Result<()> {
    client
        .get(url)
        .send()
        .await
        .with_context(|| "Could not connect to the server.")
        .with_suggestion(|| "Is shiny-donut running in listen mode on the remote server?")?;

    Ok(())
}

pub async fn client(
    host: String,
    port: u16,
    device: DeviceOption,
    security: Security,
) -> Result<()> {
    // Test conection to the server
    let client = ClientBuilder::new()
        .danger_accept_invalid_certs(true)
        .deflate(true)
        .brotli(true)
        .build()
        .with_context(|| "Could not create HTTPS client")?;

    let url = format!("https://{}:{}", host, port);
    test_connection(&url, &client).await?;

    let stream = capture::start_capture(&device.interface, port)
        .with_context(|| "Could not start the packet capture.")
        .with_suggestion(|| "Is the interface name correct and does shiny-donut have permissions to capture packets?")?;

    tokio::spawn(capture::packet_listener(stream));
    let pcap_path = capture::get_pcap_path(&device.interface);

    let api_url = url + "/traffic";
    loop {
        time::sleep(Duration::from_secs(15)).await;

        // Send post request with pcap
        client
            .post(&api_url)
            .basic_auth(&security.password, Option::<&str>::None)
            .body(File::open(&pcap_path).await?)
            .send()
            .await?;
    }

    Ok(())
}
