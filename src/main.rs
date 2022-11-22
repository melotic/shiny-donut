use clap::Parser;
use color_eyre::Result;
use pcap::Device;

mod auth;
mod capture;
mod cli;
mod networking;
mod server;

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

    match args.mode {
        cli::Mode::Server {
            port,
            device,
            security,
        } => crate::server::server(port, device, security).await?,
        cli::Mode::Client {
            host,
            port,
            security,
        } => todo!(),
        cli::Mode::Listen {
            port,
            address,
            out,
            security,
        } => todo!(),
        cli::Mode::ListDevices => list_devices()?,
    }

    Ok(())
}
