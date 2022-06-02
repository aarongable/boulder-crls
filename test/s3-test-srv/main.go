package main

import (
	"flag"
	"log"
	"net/http"

	"github.com/letsencrypt/boulder/cmd"
	blog "github.com/letsencrypt/boulder/log"
)

func main() {
	listenAddr := flag.String("listen", "localhost:7890", "Address to listen on")
	flag.Parse()

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		logger := blog.Get()
		logger.Warningf("s3-test-srv: got request: %v\n", r)
	})

	go log.Fatal(http.ListenAndServe(*listenAddr, nil))
	cmd.CatchSignals(nil, nil)
}
