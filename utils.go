package tlsx

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"log"
)

func GetServerHello(packet gopacket.Packet) *ServerHello {
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		t, _ := tcpLayer.(*layers.TCP)

		var hello = ServerHello{}
		err := hello.Unmarshal(t.LayerPayload())

		switch err {
		case nil:
		case ErrHandshakeWrongType:
			return nil
		default:
			//log.Println("Error reading Server Hello:", err)
			//spew.Dump(t.LayerPayload())
			return nil
		}

		return &hello
	} else {
		log.Println("Server Hello Reader could not decode TCP layer")
		return nil
	}
}

func GetServerHelloMinimal(packet gopacket.Packet) *ServerHello {
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		t, _ := tcpLayer.(*layers.TCP)

		var hello = ServerHello{}
		err := hello.UnmarshalMinimal(t.LayerPayload())

		switch err {
		case nil:
		case ErrHandshakeWrongType:
			return nil
		default:
			//log.Println("Error reading Server Hello:", err)
			//spew.Dump(t.LayerPayload())
			return nil
		}

		return &hello
	} else {
		log.Println("Server Hello Reader could not decode TCP layer")
		return nil
	}
}

func GetClientHello(packet gopacket.Packet)  *ClientHello {
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		t, _ := tcpLayer.(*layers.TCP)

		var hello = ClientHello{}

		err := hello.Unmarshal(t.LayerPayload())

		switch err {
		case nil:
		case ErrHandshakeWrongType:
			return nil
		default:
			//log.Println("Error reading Client Hello:", err)
			//log.Println("Raw Client Hello:", t.LayerPayload())
			return nil
		}

		return &hello
	} else {
		log.Println("Client Hello Reader could not decode TCP layer")
		return nil
	}
}

func GetClientHelloMinimal(packet gopacket.Packet)  *ClientHello {
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {

		t, _ := tcpLayer.(*layers.TCP)
		var hello = ClientHello{}

		err := hello.UnmarshalMinimal(t.LayerPayload())
		switch err {
		case nil:
		case ErrHandshakeWrongType:
			return nil
		default:
			//log.Println("Error reading Client Hello:", err)
			//log.Println("Raw Client Hello:", t.LayerPayload())
			return nil
		}

		return &hello
	} else {
		log.Println("Client Hello Reader could not decode TCP layer")
		return nil
	}
}
