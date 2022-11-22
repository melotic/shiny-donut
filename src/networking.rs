use crate::networking::eyre::eyre;
use aes_gcm::{aead::Aead, Aes256Gcm};
use bincode::{config, Decode, Encode};
use color_eyre::{eyre, Result};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
};

#[derive(Encode, Decode, Debug)]
pub enum Message {
    Ping,
    Pong,
    Pcap(Vec<u8>),
}

/// Represents network traffic sent over the internet between shiny-donut applications
#[derive(Encode, Decode)]
pub struct ShinyDonutMessage {
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

pub async fn send_message(
    msg: Message,
    mut stream: impl AsyncWriteExt + Unpin,
    key: &Aes256Gcm,
) -> Result<()> {
    let msg = bincode::encode_to_vec(&msg, config::standard())?;

    let nonce: [u8; 12] = rand::random();
    let ciphertext = key
        .encrypt(&nonce.into(), msg.as_slice())
        .map_err(|e| eyre!("Failed to encrypt the message: {}", e))?;

    let msg = ShinyDonutMessage { nonce, ciphertext };
    let msg = bincode::encode_to_vec(&msg, config::standard())?;

    stream.write_u64(msg.len() as u64).await?;
    stream.write_all(&msg).await?;

    Ok(())
}

pub async fn recv_message(
    mut stream: impl AsyncReadExt + Unpin,
    key: &Aes256Gcm,
) -> Result<Message> {
    let msg_len = stream.read_u64().await?;

    // limit is 256mb
    if msg_len > 256 * 1024 * 1024 {
        return Err(eyre!("Message too long"));
    }

    let mut buf = Vec::with_capacity(msg_len as usize);
    stream.read_buf(&mut buf).await?;

    let msg = bincode::decode_from_slice(&buf, config::standard())?.0;
    let ShinyDonutMessage { nonce, ciphertext } = msg;

    let msg = key
        .decrypt(&nonce.into(), ciphertext.as_slice())
        .map_err(|e| eyre!("Failed to decrypt the message: {}", e))?;

    let msg = bincode::decode_from_slice(msg.as_slice(), config::standard())?.0;

    Ok(msg)
}
