package tinydns

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/miekg/dns"
	"github.com/projectdiscovery/hmap/store/hybrid"
	sliceutil "github.com/projectdiscovery/utils/slice"
)

type TinyDNS struct {
	options    *Options
	server     *dns.Server
	hmv4       *hybrid.HybridMap
	hmv6       *hybrid.HybridMap
	OnServeDns func(data Info)
}

type Info struct {
	Domain    string
	Operation string
	Wildcard  bool
	Msg       string
	Upstream  string
}

func New(options *Options) (*TinyDNS, error) {
	hmv4, err := hybrid.New(hybrid.DefaultDiskOptions)
	hmv6, err := hybrid.New(hybrid.DefaultDiskOptions)
	if err != nil {
		return nil, err
	}

	tinydns := &TinyDNS{
		options: options,
		hmv4:    hmv4,
		hmv6:    hmv6,
	}

	srv := &dns.Server{
		Addr:    options.ListenAddr,
		Net:     options.Net,
		Handler: tinydns,
	}
	tinydns.server = srv

	return tinydns, nil
}

func (t *TinyDNS) GetUpstreamServer(domain string) (upstreamserver string, extDomain bool) {
	exts := GetExts()
	isExtDomain, upServerGroup := exts.IsExtDomain(domain)
	if isExtDomain {
		extUpServer := t.options.UpServerMap[upServerGroup]
		log.Printf("upServerGroup: %s extUpServer: %s", upServerGroup, extUpServer)
		return sliceutil.PickRandom(extUpServer), true
	} else {
		return sliceutil.PickRandom(t.options.DefaultUpServer), false
	}
}

func (t *TinyDNS) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	var info Info
	domain := r.Question[0].Name
	domainlookup := strings.TrimSuffix(domain, ".")
	info.Domain = domainlookup
	info.Operation = "request"
	info.Msg = fmt.Sprintf("Received request for: %s\n", domainlookup)
	if t.OnServeDns != nil {
		t.OnServeDns(info)
	}
	switch r.Question[0].Qtype {
	case dns.TypeAAAA:
		if dnsRecordBytes, ok := t.hmv6.Get(domain); ok { // - cache
			dnsRecord := &DnsRecord{}
			err := gob.NewDecoder(bytes.NewReader(dnsRecordBytes)).Decode(dnsRecord)
			if err == nil {
				info.Domain = domainlookup
				info.Operation = "cached"
				info.Wildcard = false
				info.Msg = fmt.Sprintf("Using cached AAAA record for %s record: %s.\n", domainlookup, dnsRecord)
				if t.OnServeDns != nil {
					t.OnServeDns(info)
				}
				_ = w.WriteMsg(reply(r, domain, dnsRecord))
				return
			}
		}
	case dns.TypeA:
		if dnsRecordBytes, ok := t.hmv4.Get(domain); ok { // - cache
			dnsRecord := &DnsRecord{}
			err := gob.NewDecoder(bytes.NewReader(dnsRecordBytes)).Decode(dnsRecord)
			if err == nil {
				info.Domain = domainlookup
				info.Operation = "cached"
				info.Wildcard = false
				info.Msg = fmt.Sprintf("Using cached A record for %s record %s.\n", domainlookup, dnsRecord)
				if t.OnServeDns != nil {
					t.OnServeDns(info)
				}
				_ = w.WriteMsg(reply(r, domain, dnsRecord))
				return
			}
		}
	}

	upstreamServer, extDomain := t.GetUpstreamServer(domainlookup)
	info.Domain = domainlookup
	info.Operation = "cached"
	info.Wildcard = false
	info.Upstream = upstreamServer
	info.Msg = fmt.Sprintf("Retrieving records for %s with upstream %s.\n", domainlookup, upstreamServer)
	if t.OnServeDns != nil {
		t.OnServeDns(info)
	}
	var msg *dns.Msg
	var err error
	if extDomain && t.options.LocalAddr != "0.0.0.0:53" {
		msg, err = dns.ExchangeWithSource(r, upstreamServer, t.options.LocalAddr)
	} else {
		msg, err = dns.Exchange(r, upstreamServer)
	}
	if err == nil {
		_ = w.WriteMsg(msg)
		dnsRecord := &DnsRecord{}
		for _, record := range msg.Answer {
			switch recordType := record.(type) {
			case *dns.AAAA:
				dnsRecord.AAAA = append(dnsRecord.AAAA, recordType.AAAA.String())
				log.Printf("AAAAA record %s", dnsRecord.AAAA)
				if extDomain {
					addExtsSetElement(t.options.V6set, recordType.AAAA.String())
				}
			case *dns.A:
				dnsRecord.A = append(dnsRecord.A, recordType.A.String())
				log.Printf("A record %s", dnsRecord.A)
				if extDomain {
					addExtsSetElement(t.options.V4set, recordType.A.String())
				}
			}
		}
		var dnsRecordBytes bytes.Buffer
		if err := gob.NewEncoder(&dnsRecordBytes).Encode(dnsRecord); err == nil {
			info.Domain = domainlookup
			info.Operation = "saving"
			info.Wildcard = false
			info.Upstream = upstreamServer
			info.Msg = fmt.Sprintf("Saving records for %s record %sin cache.\n", domainlookup, dnsRecord)
			if t.OnServeDns != nil {
				t.OnServeDns(info)
			}
			switch r.Question[0].Qtype {
			case dns.TypeAAAA:
				_ = t.hmv6.Set(domain, dnsRecordBytes.Bytes())
			case dns.TypeA:
				_ = t.hmv4.Set(domain, dnsRecordBytes.Bytes())
			}
		}
		_ = w.WriteMsg(reply(r, domain, &DnsRecord{}))
	}
}

func reply(r *dns.Msg, domain string, dnsRecord *DnsRecord) *dns.Msg {
	msg := dns.Msg{}
	msg.SetReply(r)
	msg.Authoritative = true
	for _, a := range dnsRecord.A {
		msg.Answer = append(msg.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: domain, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP(a),
		})
	}
	for _, aaaa := range dnsRecord.AAAA {
		msg.Answer = append(msg.Answer, &dns.AAAA{
			Hdr:  dns.RR_Header{Name: domain, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
			AAAA: net.ParseIP(aaaa),
		})
	}
	return &msg
}

func (t *TinyDNS) Run() error {
	return t.server.ListenAndServe()
}

func (t *TinyDNS) Close() {
	t.hmv4.Close()
	t.hmv6.Close()
}
