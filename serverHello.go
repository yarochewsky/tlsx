package tlsx

import (
	"errors"
	"fmt"
	"golang.org/x/crypto/cryptobyte"
)

const (
	ServerHelloRandomLen = 32
)

// CurveID is the type of a TLS identifier for an elliptic curve. See
// https://www.iana.org/assignments/tls-parameters/tls-parameters.xml#tls-parameters-8.
type CurveID uint16

type ServerHello struct {
	Raw                          []byte
	Vers                         uint16
	Random                       []byte
	SessionId                    []byte
	CipherSuite                  uint16
	CompressionMethod            uint8
	NextProtoNeg                 bool
	NextProtos                   []string
	OcspStapling                 bool
	Scts                         [][]byte
	Ems                          bool
	TicketSupported              bool
	SecureRenegotiation          []byte
	SecureRenegotiationSupported bool
	AlpnProtocol                 string
	Extensions []uint16

	// 1.3
	SupportedVersion        uint16
	ServerShare             keyShare
	SelectedIdentityPresent bool
	SelectedIdentity        uint16
	Cookie                  []byte  // HelloRetryRequest extension
	SelectedGroup           CurveID // HelloRetryRequest extension
}

// TLS 1.3 Key Share. See RFC 8446, Section 4.2.8.
type keyShare struct {
	group CurveID
	data  []byte
}

// readUint8LengthPrefixed acts like s.ReadUint8LengthPrefixed, but targets a
// []byte instead of a cryptobyte.String.
func readUint8LengthPrefixed(s *cryptobyte.String, out *[]byte) bool {
	return s.ReadUint8LengthPrefixed((*cryptobyte.String)(out))
}


// readUint16LengthPrefixed acts like s.ReadUint16LengthPrefixed, but targets a
// []byte instead of a cryptobyte.String.
func readUint16LengthPrefixed(s *cryptobyte.String, out *[]byte) bool {
	return s.ReadUint16LengthPrefixed((*cryptobyte.String)(out))
}

// TLS extension numbers
const (
	extensionServerName              uint16 = 0
	extensionStatusRequest           uint16 = 5
	extensionSupportedCurves         uint16 = 10 // supported_groups in TLS 1.3, see RFC 8446, Section 4.2.7
	extensionSupportedPoints         uint16 = 11
	extensionSignatureAlgorithms     uint16 = 13
	extensionALPN                    uint16 = 16
	extensionSCT                     uint16 = 18
	extensionSessionTicket           uint16 = 35
	extensionPreSharedKey            uint16 = 41
	extensionEarlyData               uint16 = 42
	extensionSupportedVersions       uint16 = 43
	extensionCookie                  uint16 = 44
	extensionPSKModes                uint16 = 45
	extensionCertificateAuthorities  uint16 = 47
	extensionSignatureAlgorithmsCert uint16 = 50
	extensionKeyShare                uint16 = 51
	extensionNextProtoNeg            uint16 = 13172 // not IANA assigned
	extensionRenegotiationInfo       uint16 = 0xff01
)

type serverHelloMsg struct {
	raw                          []byte
	vers                         uint16
	random                       []byte
	sessionId                    []byte
	cipherSuite                  uint16
	compressionMethod            uint8
	nextProtoNeg                 bool
	nextProtos                   []string
	ocspStapling                 bool
	ticketSupported              bool
	secureRenegotiationSupported bool
	secureRenegotiation          []byte
	alpnProtocol                 string
	ems                          bool
	scts                         [][]byte
	supportedVersion             uint16
	serverShare                  keyShare
	selectedIdentityPresent      bool
	selectedIdentity             uint16

	// HelloRetryRequest extensions
	cookie        []byte
	selectedGroup CurveID

	extensions []uint16
}

func (msg *ServerHello) Unmarshall(buf []byte) error {

	if len(buf) < 5+4 {
		return errors.New("Server returned short message")
	}

	// buf contains a TLS record, with a 5 byte record header and a 4 byte
	// handshake header. The length of the ServerHello is taken from the
	// handshake header.
	serverHelloLen := int(buf[6])<<16 | int(buf[7])<<8 | int(buf[8])

	if serverHelloLen >= len(buf) {
		return errors.New("invalid serverHelloLen")
	}

	var shm serverHelloMsg
	if err := shm.unmarshal(buf[5 : 9+serverHelloLen]); err != nil {
		return err
	}

	msg.Raw =                          shm.raw
	msg.Vers =                         shm.vers
	msg.Random =                       shm.random
	msg.SessionId =                    shm.sessionId
	msg.CipherSuite =                  shm.cipherSuite
	msg.CompressionMethod =            shm.compressionMethod
	msg.NextProtoNeg =                 shm.nextProtoNeg
	msg.NextProtos =                   shm.nextProtos
	msg.OcspStapling =                 shm.ocspStapling
	msg.Scts =                         shm.scts
	msg.Ems =                          shm.ems
	msg.TicketSupported =              shm.ticketSupported
	msg.SecureRenegotiation =          shm.secureRenegotiation
	msg.SecureRenegotiationSupported = shm.secureRenegotiationSupported
	msg.AlpnProtocol =                 shm.alpnProtocol
	msg.SupportedVersion =             shm.supportedVersion
	msg.ServerShare =                  shm.serverShare
	msg.SelectedIdentityPresent =      shm.selectedIdentityPresent
	msg.SelectedIdentity =             shm.selectedIdentity
	msg.Cookie =                       shm.cookie
	msg.SelectedGroup =                shm.selectedGroup
	msg.Extensions = shm.extensions

	return nil
}

func (m *serverHelloMsg) unmarshal(data []byte) error {

	*m = serverHelloMsg{raw: data}
	s := cryptobyte.String(data)

	if !s.Skip(4) || // message type and uint24 length field
		!s.ReadUint16(&m.vers) || !s.ReadBytes(&m.random, 32) ||
		!readUint8LengthPrefixed(&s, &m.sessionId) ||
		!s.ReadUint16(&m.cipherSuite) ||
		!s.ReadUint8(&m.compressionMethod) {
		if m.vers == 772 {
			fmt.Println("TLS 1.3 !!!")
		}
		return errors.New("invalid message type")
	}

	if s.Empty() {
		// ServerHello is optionally followed by extension data
		return nil
	}

	var extensions cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&extensions) || !s.Empty() {
		return errors.New("failed to read extensions")
	}

	for !extensions.Empty() {
		var extension uint16
		var extData cryptobyte.String
		if !extensions.ReadUint16(&extension) ||
			!extensions.ReadUint16LengthPrefixed(&extData) {
			return errors.New("failed to read extension data")
		}

		m.extensions = append(m.extensions, extension)

		switch extension {
		case extensionNextProtoNeg:
			m.nextProtoNeg = true
			for !extData.Empty() {
				var proto cryptobyte.String
				if !extData.ReadUint8LengthPrefixed(&proto) ||
					proto.Empty() {
					return errors.New("failed to read extensionNextProtoNeg")
				}
				m.nextProtos = append(m.nextProtos, string(proto))
			}
		case extensionStatusRequest:
			m.ocspStapling = true
		case extensionSessionTicket:
			m.ticketSupported = true
		case extensionRenegotiationInfo:
			if !readUint8LengthPrefixed(&extData, &m.secureRenegotiation) {
				return errors.New("failed to read extensionRenegotiationInfo")
			}
			m.secureRenegotiationSupported = true
		case extensionALPN:
			var protoList cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&protoList) || protoList.Empty() {
				return errors.New("failed to read extensionALPN protoList")
			}
			var proto cryptobyte.String
			if !protoList.ReadUint8LengthPrefixed(&proto) ||
				proto.Empty() || !protoList.Empty() {
				return errors.New("failed to read extensionRenegotiationInfo proto")
			}
			m.alpnProtocol = string(proto)
		case extensionSCT:
			var sctList cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&sctList) || sctList.Empty() {
				return errors.New("failed to read extensionSCT sctList")
			}
			for !sctList.Empty() {
				var sct []byte
				if !readUint16LengthPrefixed(&sctList, &sct) ||
					len(sct) == 0 {
					return errors.New("failed to read extensionSCT sctList sct")
				}
				m.scts = append(m.scts, sct)
			}
		case extensionSupportedVersions:
			if !extData.ReadUint16(&m.supportedVersion) {
				return errors.New("failed to read extensionSupportedVersions")
			}
		case extensionCookie:
			if !readUint16LengthPrefixed(&extData, &m.cookie) ||
				len(m.cookie) == 0 {
				return errors.New("failed to read extensionCookie")
			}
		case extensionKeyShare:
			// This extension has different formats in SH and HRR, accept either
			// and let the handshake logic decide. See RFC 8446, Section 4.2.8.
			if len(extData) == 2 {
				if !extData.ReadUint16((*uint16)(&m.selectedGroup)) {
					return errors.New("failed to read extensionKeyShare")
				}
			} else {
				if !extData.ReadUint16((*uint16)(&m.serverShare.group)) ||
					!readUint16LengthPrefixed(&extData, &m.serverShare.data) {
					return errors.New("failed to read extensionKeyShare")
				}
			}
		case extensionPreSharedKey:
			m.selectedIdentityPresent = true
			if !extData.ReadUint16(&m.selectedIdentity) {
				return errors.New("failed to read extensionPreSharedKey")
			}
		default:
			// Ignore unknown extensions.
			continue
		}

		if !extData.Empty() {
			return errors.New("failed to read extension data")
		}
	}

	return nil
}

//func (ch ServerHello) String() string {
//	str := fmt.Sprintln("Version:", ch.Version)
//	str += fmt.Sprintln("Handshake Type:", ch.HandshakeType)
//	str += fmt.Sprintln("Handshake Version:", ch.HandshakeVersion)
//	str += fmt.Sprintf("SessionID: %#v\n", ch.SessionID)
//	str += fmt.Sprintf("Cipher Suites (%d): %v\n", ch.CipherSuiteLen, ch.CipherSuites)
//	str += fmt.Sprintf("Compression Methods: %v\n", ch.CompressMethods)
//	str += fmt.Sprintln("Extensions:", ch.Extensions)
//	str += fmt.Sprintf("SNI: %q\n", ch.SNI)
//	str += fmt.Sprintf("Signature Algorithms: %#v\n", ch.SignatureAlgs)
//	str += fmt.Sprintf("Groups: %#v\n", ch.SupportedGroups)
//	str += fmt.Sprintf("Points: %#v\n", ch.SupportedPoints)
//	str += fmt.Sprintf("OSCP: %v\n", ch.OSCP)
//	str += fmt.Sprintf("ALPNs: %v", ch.ALPNs)
//	return str
//}
