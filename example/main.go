package main

import (
	//"encoding/hex"
	"flag"
	"fmt"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/dreadl0ck/tlsx"
	"github.com/google/gopacket"
	"log"
)

func main() {

	var (
		flagInterface = flag.String("iface", "en0", "Network interface to capture on")
		flagPcap = flag.String("pcap", "", "use pcap file")
		flagBPF = flag.String("bpf", "tcp", "bpf filter")
	)

	flag.Parse()

	var (
		handle *pcap.Handle
		err error
	)

	if *flagPcap != "" {
		handle, err = pcap.OpenOffline(*flagPcap)
	} else {
		handle, err = pcap.OpenLive(*flagInterface, 1514, false, pcap.BlockForever)
	}
	if err != nil {
		log.Fatal(err)
	}

	// set bpf
	err = handle.SetBPFFilter(*flagBPF)
	if err != nil {
		log.Fatal(err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	fmt.Println("Listening on", *flagInterface)
	for packet := range packetSource.Packets() {
		go readPacket(packet)
	}
}

func readPacket(packet gopacket.Packet) {
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, ok := tcpLayer.(*layers.TCP)
		if !ok {
			log.Println("Could not decode TCP layer")
			return
		}

		//fmt.Println(tcp.ACK, tcp.Seq)

		if tcp.SYN {
			// Connection setup
		} else if tcp.FIN {
			// Connection teardown
		} else if tcp.ACK && len(tcp.LayerPayload()) == 0 {
			// Acknowledgement packet
		} else if tcp.RST {
			// Unexpected packet
		} else {
			// data packet

			// TLS client hello
			clientHello := tlsx.GetClientHello(packet)
			if clientHello != nil {
				destination := "[" + packet.NetworkLayer().NetworkFlow().Dst().String() + ":"+ packet.TransportLayer().TransportFlow().Dst().String() + "]"
				log.Printf("%s Client hello from port %s to %s", destination, tcp.SrcPort, tcp.DstPort)
			}

			// TLS server hello
			serverHello := tlsx.GetServerHello(packet)
			if serverHello != nil {
				destination := "[" + packet.NetworkLayer().NetworkFlow().Dst().String() + ":"+ packet.TransportLayer().TransportFlow().Dst().String() + "]"
				log.Printf("%s Client hello from port %s to %s", destination, tcp.SrcPort, tcp.DstPort)
			}
		}
	}
}

