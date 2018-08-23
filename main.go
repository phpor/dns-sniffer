package main

import (
	"github.com/google/gopacket/pcap"
	"flag"
	"github.com/google/gopacket"
	"net"
	"fmt"
	"github.com/google/gopacket/layers"
	"time"
	"github.com/davecgh/go-spew/spew"
	"encoding/json"
)

var verbose = false

type DNSQuery struct {
	SrcIP, DstIP gopacket.Endpoint
	SrcPort, DstPort gopacket.Endpoint
	Request      bool
	Query        []layers.DNSQuestion
	Timestamp    time.Time
}

type QA struct {
	Question *DNSQuery
	Answer *layers.DNS
	Time time.Duration
}

type DNSAnswer struct {
	Answer       string
	Query        string
	SrcIP, DstIP net.IP
	Request      bool
	Timestamp    int64
	Type         string
	TTL          uint32
}



var buf = struct {
	data map[string]DNSQuery
}{data: make(map[string]DNSQuery)}


func main() {

	var filter *string = flag.String("f", "udp and port 53", "filter same as tcpdump")
	var eth *string = flag.String("i", "eth0", "Interface to sniff")
	flag.Parse()

	packets := make(chan gopacket.Packet)
	handle, err := pcap.OpenLive(*eth, 1600, true, 0)
	assertNil(err)

	err = handle.SetBPFFilter(*filter)
	assertNil(err)
	go func() {
		deal(packets)
	}()
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		packets <- packet
	}
}

func deal(packets chan gopacket.Packet) {

	for packet := range packets {
		nlayer := packet.NetworkLayer()
		assertNotNil(nlayer, "parse network layer fail")
		src, dst := nlayer.NetworkFlow().Endpoints()
		fmt.Println(src.String(), dst.String())

		tlayer := packet.TransportLayer()
		assertNotNil(tlayer, "parse transport layer fail")
		srcPort, dstPort := tlayer.TransportFlow().Endpoints()
		fmt.Println(srcPort.String(), dstPort.String())

		dnslayer := packet.Layer(layers.LayerTypeDNS)
		assertNotNil(dnslayer, "parse dns layer fail")

		dns := &layers.DNS{}
		dns.DecodeFromBytes(dnslayer.LayerContents(), gopacket.NilDecodeFeedback)
		//debug(dns)
		id := dns.ID
		var transId string
		if ! dns.QR {
			transId = fmt.Sprintf("%s:%s,%s:%s,%d", src.String(), srcPort.String(), dst.String(), dstPort.String(), id)
			debug(transId)
			dnsQuery := DNSQuery{
				SrcIP: src,
				DstIP: dst,
				SrcPort: srcPort,
				DstPort: dstPort,
				Query: dns.Questions,
				Timestamp: time.Now(),

			}
			buf.data[transId] = dnsQuery
			continue
		}
		transId = fmt.Sprintf("%s:%s,%s:%s,%d", dst.String(), dstPort.String(), src.String(), srcPort.String(), id)
		debug(transId)

		dnsQuery, ok := buf.data[transId]
		if !ok {
			continue
		}
		debug(dnsQuery.Query)
		debug(dns.Answers)
		output, err := json.Marshal(&QA{
			Question: &dnsQuery,
			Answer: dns,
			Time: time.Now().Sub(dnsQuery.Timestamp),
		})
		assertNil(err)
		fmt.Println(string(output))
	}
}


func assertNil(o interface{}) {
	if o != nil {
		panic(o)
	}
}

func assertNotNil (o interface{}, msg string) {
	if o == nil {
		panic(msg)
	}
}

func debug(msg ... interface{}) {
	if verbose {
		spew.Dump(msg...)
	}
}