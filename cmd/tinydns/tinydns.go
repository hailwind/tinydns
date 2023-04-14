package main

import (
	"log"
	"os"
	"os/signal"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/tinydns"
)

func main() {
	options := &tinydns.Options{}
	tinydns.LoadOptions(options)
	log.Printf("options.UpServerMap: %s", options.UpServerMap)
	tdns, err := tinydns.New(options)
	if err != nil {
		gologger.Fatal().Msgf("Could not create tinydns instance: %s\n", err)
	}
	gologger.Info().Msgf("Listening on: %s:%s\n", options.Net, options.ListenAddr)
	tdns.OnServeDns = func(data tinydns.Info) {
		gologger.Info().Msgf("%s", data.Msg)
	}

	// Setup graceful exits
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		for range c {
			gologger.Info().Msgf("CTRL+C pressed: Exiting\n")
			tdns.Close()
			os.Exit(1)
		}
	}()

	err = tdns.Run()
	if err != nil {
		gologger.Fatal().Msgf("Could not run tinydns server: %s\n", err)
	}
}
