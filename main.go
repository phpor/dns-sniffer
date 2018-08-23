package main

import (
	"github.com/google/gopacket/pcap"
	"flag"
	"github.com/google/gopacket"
	"fmt"
	"github.com/google/gopacket/layers"
	"time"
	"github.com/davecgh/go-spew/spew"
	"encoding/json"
)

var verbose = false

type question struct {
	Name  string
	Type  string
	Class string
}
type resourceRecord struct {
	// Header
	Name  string
	Type  string
	Class string
	TTL   uint32

	// RDATA Raw Values
	DataLength uint16
	Data       string

	// RDATA Decoded Values
	IP             string
	NS, CNAME, PTR string
	TXTs           []string
	SOA            string
	SRV            string
	MX             string

	// Undecoded TXT for backward compatibility
	TXT string
}
type DNSQuery struct {
	SrcIP, DstIP string
	SrcPort, DstPort string
	Request      bool
	Query        []question
	Timestamp    time.Time
}

type QA struct {
	Question *DNSQuery
	Answer []resourceRecord
	Time time.Duration
}

var buf = struct {
	data map[string]DNSQuery
}{data: make(map[string]DNSQuery)}


func main() {

	var filter = flag.String("f", "udp and port 53", "filter same as tcpdump")
	var eth    = flag.String("i", "eth0", "Interface to sniff")
	verbose = *flag.Bool("v", false, "Print debuginfo")

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
		debug(src.String(), dst.String())

		tlayer := packet.TransportLayer()
		assertNotNil(tlayer, "parse transport layer fail")
		srcPort, dstPort := tlayer.TransportFlow().Endpoints()
		debug(srcPort.String(), dstPort.String())

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
			questions := convertQuestion(dns.Questions)
			dnsQuery := DNSQuery{
				SrcIP: src.String(),
				DstIP: dst.String(),
				SrcPort: srcPort.String(),
				DstPort: dstPort.String(),
				Query: questions,
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
		records := convertAnswer(dns.Answers)
		output, err := json.Marshal(&QA{
			Question: &dnsQuery,
			Answer: records,
			Time: time.Now().Sub(dnsQuery.Timestamp),
		})
		assertNil(err)
		fmt.Println(string(output))
	}
}

func convertQuestion(Questions []layers.DNSQuestion) []question {
	questions := []question{}
	for _,item := range Questions {
		q := question{
			Name: string(item.Name),
			Type: item.Type.String(),
			Class: item.Class.String(),
		}
		questions = append(questions, q)
	}
	return questions
}
func convertAnswer(answers []layers.DNSResourceRecord)[]resourceRecord {
	records := []resourceRecord{}
	for _, item := range answers {
		r := resourceRecord{
			Name: string(item.Name),
			Type: item.Type.String(),
			Class: item.Class.String(),
			TTL: item.TTL,
			DataLength: item.DataLength,
			Data: string(item.Data),
			IP: item.IP.String(),
			NS: string(item.NS),
			CNAME: string(item.CNAME),
			PTR: string(item.PTR),
			// todo : SOA SRV MX not convert
			TXT: string(item.TXT),
		}
		for _, s := range item.TXTs {
			r.TXTs =  append(r.TXTs, string(s))
		}
		records = append(records, r)
	}
	return records
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