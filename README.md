# Introduction

[![GoDoc](https://godoc.org/github.com/dreadl0ck/tlsx?status.svg)](https://godoc.org/github.com/dreadl0ck/tlsx)

This is a fork of the **bradleyfalzon/tlsx** package,
that was updated to store TLS extensions in the client hello message in the order they were encountered during parsing.
It was further extended with unit tests, benchmarks and parsing code to extract the TLS server hello message.

This package is used to create JA3 hashes, for fingerprinting TLS client and server hellos in **github.com/dreadl0ck/ja3**.
Since not all values produced by parsing the hello messages are required to calculate the fingerprint,
two variations of the Unmarshal function are provided for both client and server: *Unmarshal()* and *UnmarshalMinimal()*.
The minimal unmarshal will only parse the raw values without populating the entire structs, and therefore are slightly faster.

## API

    package tlsx // import "github.com/dreadl0ck/tlsx"
    
    const SNINameTypeDNS uint8 = 0 ...
    const ClientHelloRandomLen = 32
    const ServerHelloRandomLen = 32
    var ErrHandshakeWrongType = errors.New("handshake is of wrong type, or not a handshake message") ...
    var CipherSuiteReg = map[CipherSuite]string{ ... }
    var ExtensionReg = map[Extension]string{ ... }
    var VersionReg = map[Version]string{ ... }
    type CipherSuite uint16
    type ClientHello struct{ ... }
        func GetClientHello(packet gopacket.Packet) *ClientHello
        func GetClientHelloMinimal(packet gopacket.Packet) *ClientHello
    type CurveID uint16
    type Extension uint16
        const ExtServerName Extension = 0 ...
    type ServerHello struct{ ... }
        func GetServerHello(packet gopacket.Packet) *ServerHello
        func GetServerHelloMinimal(packet gopacket.Packet) *ServerHello
    type TLSMessage struct{ ... }
    type Version uint16
        const VerSSL30 Version = 0x300 ...

## Tests and Benchmarks

Benchmarks:

    $ go test -bench=.
    goos: darwin
    goarch: amd64
    pkg: github.com/dreadl0ck/tlsx
    BenchmarkGetClientHello-12           	 1380427	       899 ns/op	     688 B/op	      16 allocs/op
    BenchmarkGetClientHelloMinimal-12    	 2741461	       438 ns/op	     488 B/op	       8 allocs/op
    BenchmarkGetServerHello-12           	 4232562	       278 ns/op	     336 B/op	       3 allocs/op
    BenchmarkGetServerHelloMinimal-12    	 4691030	       234 ns/op	     328 B/op	       2 allocs/op
    PASS
    ok  	github.com/dreadl0ck/tlsx	6.673s

Tests:

    $ go test -v
    === RUN   TestClientHello
    --- PASS: TestClientHello (0.00s)
    === RUN   TestClientHelloMinimal
    --- PASS: TestClientHelloMinimal (0.00s)
    === RUN   TestServerHello
    --- PASS: TestServerHello (0.00s)
    === RUN   TestGetServerHelloMinimal
    --- PASS: TestGetServerHelloMinimal (0.00s)
    PASS
    ok  	github.com/dreadl0ck/tlsx	0.067s