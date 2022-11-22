# shiny-donut

shiny-donut is a packet capture app that supports streaming packets from a remote system to another device. The main use for this is to send pcaps to another device for other analysis.

## Modes

shiny-donuts supports two modes to capture packets:

1. Server mode: shiny-donut listens on a configurable port to receive packets from a remote system. Packets are then written to a pcap file on another machine.
2. Client mode: shiny-donut streams pcaps to a remote system, who is listening for incoming connection from shiny-donut.