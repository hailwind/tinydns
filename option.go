package tinydns

import (
	"encoding/json"
	"log"
	"os"
)

type Options struct {
	ListenAddr      string
	Net             string
	LocalAddr       string
	DefaultUpServer []string
	UpServerMap     map[string][]string
	// TTL             time.Duration
	// UpstreamServers_i []string
	// UpstreamServers_e []string
}

func LoadConfig(path string, pointer any) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	buff := make([]byte, 4096)
	if n, err := f.Read(buff[:]); err == nil {
		// log.Printf("len: %d", n)
		if err2 := json.Unmarshal(buff[:n], pointer); err2 == nil { //反序列化
			return nil
		} else {
			return err2
		}
	} else {
		return err
	}
}

func LoadOptions(options *Options) {
	err := LoadConfig("/etc/tinydns.json", options)
	if err != nil {
		log.Printf("load options err: %s", err)
		os.Exit(1)
	}
}
