package tinydns

import (
	"log"
	"net"

	"github.com/google/nftables"
)

func addExtsSetElement(set string, val string) {
	log.Printf("set: %s val: %s", set, val)
	conn, err := nftables.New()
	if err != nil {
		log.Printf("err: %s", err)
		return
	}
	defer conn.CloseLasting()
	tables, err1 := conn.ListTables()
	if err1 != nil {
		log.Printf("err1: %s", err1)
		return
	}
	var gfw *nftables.Table
	for _, table := range tables {
		if table.Name == "gfw" {
			gfw = table
		}
	}
	exts, err2 := conn.GetSetByName(gfw, set)
	if err2 != nil {
		log.Printf("err2: %s", err2)
		return
	}
	var elements []nftables.SetElement
	if set == "exts6" {
		elements = []nftables.SetElement{{Key: []byte(net.ParseIP(val))}}
	} else {
		elements = []nftables.SetElement{{Key: []byte(net.ParseIP(val).To4())}}
	}
	err3 := conn.SetAddElements(exts, elements)
	if err3 != nil {
		log.Printf("err3: %s", err3)
		return
	}
	if errx := conn.Flush(); errx != nil {
		log.Printf("errx: %s", errx)
	}
}
