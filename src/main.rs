use clap::Parser;
use color_eyre::Result;
use pcap::Device;

mod auth;
mod capture;
mod cli;
mod client;
mod listen;
mod server;

const SHINY_DONUT_LOGO: &str = include_str!("../static/logo.txt");

#[derive(Parser)]
#[clap(version, author, about)]
struct Args {
    #[clap(subcommand)]
    mode: cli::Mode,
}

fn list_devices() -> Result<()> {
    for dev in Device::list()? {
        println!("{}", dev.name);
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    // start capturing packets
    let args = Args::parse();

    tracing_subscriber::fmt::init();
    color_eyre::install()?;

    match args.mode {
        cli::Mode::Server {
            port,
            device,
            security,
        } => crate::server::server(port, device, security).await?,
        cli::Mode::Client {
            host,
            port,
            device,
            security,
        } => crate::client::client(host, port, device, security).await?,
        cli::Mode::Listen {
            port,
            address,
            security,
        } => crate::listen::listen(address, port, security).await?,
        cli::Mode::ListDevices => list_devices()?,
    }

    Ok(())
}
