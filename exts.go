package tinydns

import (
	"log"
	"os"
	"regexp"
	"strings"
)

const extsPath = "/etc/exts.conf"

type Exts struct {
	Domains      map[string]string
	DomainsRegex map[string]*regexp.Regexp
}

func (exts *Exts) LoadDomains() {
	f, err := os.Open(extsPath)
	if err != nil {
		return
	}
	defer f.Close()
	buff := make([]byte, 102400)
	if n, err := f.Read(buff[:]); err == nil {
		strs := string(buff[:n])
		lines := strings.Split(strs, "\n")
		for _, line := range lines {
			// log.Printf("line: %s", line)
			arr := strings.Split(line, ":")
			if len(arr) == 2 {
				log.Printf("arr: %s", arr)
				exts.Domains[arr[0]] = arr[1]
				regstr := ".*?" + arr[0]
				reg := regexp.MustCompile(regstr)
				exts.DomainsRegex[arr[0]] = reg
			}
		}
	}
}

func (exts *Exts) IsExtDomain(domain string) (bool, string) {
	for k, reg := range exts.DomainsRegex {
		// log.Printf("k: %s", k)
		if reg.MatchString(domain) {
			return true, exts.Domains[k]
		}
	}
	return false, ""
}

var exts *Exts

func GetExts() *Exts {
	if exts == nil {
		exts = new(Exts)
		exts.Domains = make(map[string]string)
		exts.DomainsRegex = make(map[string]*regexp.Regexp)
		exts.LoadDomains()
	}
	return exts
}
