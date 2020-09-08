# Requirements
To compile and use this program the following packages are required:
- `libssl-dev`
- `gcc`
- `Go 1.14`

The program has been developed and tested using Go version `1.14.7` and `1.14.8`. Other versions of Go should work, but have not been tested.

For cloning the repository `git` might also be required.

The program was developed on Ubuntu 20.04 and has only been tested on this distribution.

# Building
1. Install Ubuntu 20.04
2. Fully update (`apt update`, `apt upgrade`, `apt autoremove`, then reboot)
3. Install git, libssl-dev and gcc (`apt install git libssl-dev gcc`)
4. Install Go 1.14.8 ([How-To](https://golang.org/doc/install))
5. Clone the repository (`git clone https://gitlab.lrz.de/netintum/teaching/p2psec_projects_2020/onion-16.git`)
6. switch to the `onion-16/implementation/src` folder
7. build (`go build`)
8. run (`./onion -c example_config.ini`)

# Limitations
The system does not make any guarantees for the reliability of the data delivery.
All message are sent on a best-effort basis.
For some delivery issues an error is returned, although the absence of an error does not indicate a successful delivery.

The amount of data per packet that the system can handle is limited.
All packets are fixed to a size of 1232 bytes and for each hop there is an additional overhead of 21 bytes per packet (16 bytes for cryptography data, 4 bytes sequence number and 1 byte message type).
Additionally, 23 bytes of data are required between each hop for the Hop Layer header.
Lastly, the TPort is used so that hops know to which tunnel an incoming packet belongs.
Therefore, the maximum size a packet can be when three intermediate hops are used is:

`1232 - 23 [Hop Layer Header] - 4 [3 intermediate hops and destination] * 21 [Onion Layer header] - 4 [TPort] = 1121` bytes.
If you require more data per packet, you will need to implement your own fragmentation and reassembly system.
Also, using more hops than three should work (although it will decrease the amount of data that can be sent per packet), however, the reliability will decrease due to the nature of sending more UDP packets that can get lost.



# Testing
To run all builtin tests execute `go test -v`

To run a single test execute `go test -v -run [TEST_NAME]`

Available tests are:
- `TestBuildTunnel` Builds a single tunnel, sends data through it and then tears down the tunnel (`ONION_TUNNEL_BUILD`, `ONION_TUNNEL_DATA`, `ONION_TUNNEL_DESTROY`)
- `TestCoverTraffic` Builds a tunnel and sends cover traffic through it (`ONION_TUNNEL_COVER`)
- `TestMultipleTunnels` Builds two tunnels in one direction and one tunnel in the other direction to test concurrent tunnel usage. Data is sent through the tunnels and they are torn down afterwards.

All peers involved in the tests write their log files to `testing_setup/peer*/onion.log`.
Since debug logging is enabled, the logs can be used to keep track of the states of the peers.