# 🍩 shiny-donut

shiny-donut is a packet capture app that supports streaming packets from a remote system to another device. The main use for this is to send pcaps to another device for other analysis, and Attack & Defend CTFs to monitor traffic.

## Building

Build shiny-donut with the following command:

```bash
$ cargo build --release
```

The binary will be available in `target/release/shiny-donut`.

## Modes

shiny-donuts supports two modes to capture packets, and one to receive them:

1. `Server mode`: shiny-donut listens on a configurable port to receive packets from a remote system. Packets are then written to a pcap file on another machine.
2. `Client mode`: shiny-donut streams pcaps to a remote system, who is listening for incoming connection from shiny-donut.
3. `Listen mode`: This is used in conjuction with `Client Mode`. Listen mode spins up an HTTPS server, to which the client mode connects to and posts the PCAP data. This mode also supports capture packets from mulitple shiny-donut instances running in `Client mode`.

## Server Mode

For server mode, first generate a HTTPS certificate with openssl:

```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365
```
To run shiny-donut in server mode, run the following command:

```bash
shiny-donut server --password <PASSWORD> <PORT> <INTERFACE>
```

This spins up an HTTPS server with two endpoints: `/`, the index page, and `/traffic`. The index page is used to prove to the client that the server is a valid shiny-donut server. The traffic endpoint is used to receive packets from the client.

To connect to `/traffic` you must use the password as the username using HTTP basic authentication. Example with curl:

```bash
curl -u <PASSWORD>: -k https://<SERVER_IP>:<PORT>/traffic --output traffic.pcap
```

## Client Mode

For client mode, first create a client that will actually recieve the packets. This can be done by running shiny-donut in listen mode on a server you'd like to recieve the packets on:

```bash
shiny-donut listen --password <PASSWORD> <PORT>
```

You'll first have to generate an HTTPS certificate with:

```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365
```

Then, run the following command to stream packets from a device to the server:

```bash
shiny-donut client --password <PASSWORD> <SERVER_IP> <PORT>
```

Then, packets will be streamed to the file in `data/<IP>.pcap` on the server.