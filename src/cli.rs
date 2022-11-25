use clap::Parser;

#[derive(Parser, PartialEq)]
pub(crate) enum Mode {
    /// Binds to a port for incoming connections to send packets to
    Server {
        /// The port to listen on
        port: u16,

        /// The device to use to capture packets
        #[command(flatten)]
        device: DeviceOption,

        #[command(flatten)]
        security: Security,
    },

    /// Streams packets to a specified server
    Client {
        /// The IP address to connect to
        host: String,

        /// The port to connect to
        port: u16,

        /// The device to use to capture packets
        #[command(flatten)]
        device: DeviceOption,

        #[command(flatten)]
        security: Security,
    },

    Listen {
        /// The port to listen on
        port: u16,

        /// The IP address to listen on
        #[clap(short, long, default_value = "0.0.0.0")]
        address: String,

        #[command(flatten)]
        security: Security,
    },

    /// Lists the interfaces that can be used to sniff packets
    ListDevices,
}

#[derive(Parser, PartialEq, Eq)]
pub struct DeviceOption {
    /// The device to use to sniff packets
    pub interface: String,
}

#[derive(Parser, PartialEq, Eq)]
pub struct Security {
    /// The password to use to authenticate with the server
    #[clap(short, long)]
    pub password: String,
}
