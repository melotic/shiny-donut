use crate::auth::generate_aes_key;
use crate::cli::Security;
use crate::networking::{recv_message, send_message, Message};
use crate::{capture, cli};
use color_eyre::Result;
use std::sync::Arc;
use tokio::select;
use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;
use tokio::{
    fs::File,
    io,
    net::TcpListener,
    sync::Mutex,
    time::{self, Duration},
};

pub async fn server(port: u16, device: cli::DeviceOption, security: Security) -> Result<()> {
    let stream = capture::start_capture(&device.interface, port)?;
    tokio::spawn(capture::packet_listener(stream));

    // Listen for connections on that port
    let listener = TcpListener::bind(format!("0.0.0.0:{}", port)).await?;
    let pcap = capture::get_pcap_path(&device.interface);

    let security_arc = Arc::new(security);

    // wait for connections
    loop {
        let (socket, addr) = listener.accept().await?;
        let (mut reader, mut writer) = socket.into_split();

        let (tx, mut rx) = mpsc::unbounded_channel();

        let pcap = pcap.clone();
        let security = security_arc.clone();

        // Send data to the client
        tokio::spawn(async move {
            let aes = generate_aes_key(&security.password);
            let interval = Duration::from_secs(15);
            let mut last_msg_sent_t = Instant::now();

            loop {
                select! {
                    _ = time::sleep(interval - last_msg_sent_t.elapsed()) => {
                         // send the pcap
                        let mut file = File::open(&pcap).await.unwrap();
                        let mut buf = Vec::new();
                        io::copy(&mut file, &mut buf).await.unwrap();

                        send_message(Message::Pcap(buf), &mut writer, &aes).await.unwrap();
                        last_msg_sent_t = Instant::now();

                        println!("Sent PCAP to {}", addr);
                    }
                    msg = rx.recv() => {
                        if let Some(msg) = msg {
                            send_message(msg, &mut writer, &aes).await.unwrap();
                        }
                    }
                }
            }
        });

        let security = security_arc.clone();
        // Parse data from the client
        tokio::spawn(async move {
            let aes = generate_aes_key(&security.password);

            loop {
                let message = recv_message(&mut reader, &aes).await.unwrap();
                match message {
                    Message::Ping => {
                        tx.send(Message::Pong).unwrap();
                    }
                    _ => println!("Unknown Message from {}.\nMessage: {:?}", addr, message),
                }
            }
        });
    }
}
