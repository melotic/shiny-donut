use color_eyre::{
    eyre::{self, Context},
    Result,
};
use futures_util::StreamExt;
use pcap::{self, Device, Packet, PacketCodec, PacketStream, Savefile};
use std::{env::temp_dir, path::PathBuf};
use tracing::{info, trace};

use crate::capture::eyre::eyre;

pub struct SaveFilePacketCodec(Savefile);

impl PacketCodec for SaveFilePacketCodec {
    type Item = ();

    fn decode(&mut self, packet: Packet) -> Self::Item {
        self.0.write(&packet);
        self.0.flush().unwrap()
    }
}

pub fn get_pcap_path(interface: &str) -> PathBuf {
    temp_dir().join(format!("shiny-donut-{}.pcap", interface))
}

pub fn start_capture(
    interface: &str,
    port: u16,
) -> Result<PacketStream<pcap::Active, SaveFilePacketCodec>> {
    // Find the device
    let mut device = Device::list()?
        .into_iter()
        .find(|dev| dev.name == interface)
        .ok_or_else(|| eyre!("Could not find device {}", interface))?
        .open()?
        .setnonblock()?;

    info!("Found device {}", interface);

    // ignore shiny-donut traffic
    device.filter(&format!("not port {}", port), true)?;

    let pcap_file = get_pcap_path(interface);
    let save_file = device.savefile(&pcap_file)?;

    info!("Saving traffic to {}", pcap_file.display());
    // Create a stream
    device
        .stream(SaveFilePacketCodec(save_file))
        .with_context(|| "failed to start capture")
}

pub async fn packet_listener(stream: PacketStream<pcap::Active, SaveFilePacketCodec>) {
    stream
        .for_each_concurrent(None, |_| async {
            trace!("Received new data");
        })
        .await;
}
