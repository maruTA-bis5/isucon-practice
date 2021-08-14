package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/newrelic/go-agent/v3/newrelic"
)

var (
	bind string
	port int
)

func init() {
	flag.StringVar(&bind, "bind", "0.0.0.0", "bind address")
	flag.IntVar(&port, "port", 9292, "bind port")

	flag.Parse()
}

func main() {
	nrLicense := os.Getenv("NEWRELIC_LICENSE")
	var nrApp *newrelic.Application
	var err error
	if nrLicense != "" {
		nrApp, err = newrelic.NewApplication(
			newrelic.ConfigAppName("i11p"),
			newrelic.ConfigLicense(nrLicense),
			newrelic.ConfigDebugLogger(os.Stdout),
			func(cfg *newrelic.Config) {
				cfg.CustomInsightsEvents.Enabled = true
			},
		)
		if err != nil {
			panic(err)
		}
	}
	srv := &http.Server{
		Addr:    fmt.Sprintf("%s:%d", bind, port),
		Handler: serveMux(nrApp),
	}

	initRedisClient(nrApp)

	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
