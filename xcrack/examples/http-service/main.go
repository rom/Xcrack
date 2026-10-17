// Command http-service embeds the Xcrack recovery engine as an HTTP API inside
// your own server — the library form of xcrackd. It shows wiring pkg/api.Server
// over a shared Pool, attaching a per-request audit hook, mounting the handler
// on your own mux alongside your own routes, optional TLS, and graceful
// shutdown. Point the xcrack client at it with `xcrack --server URL ...`.
//
// Usage:
//
//	http-service [-addr :8080] [-tls-cert FILE -tls-key FILE]
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rom/xcrack/pkg/api"
	"github.com/rom/xcrack/pkg/xcrack"
)

func main() {
	addr := flag.String("addr", ":8080", "listen address")
	tlsCert := flag.String("tls-cert", "", "PEM certificate chain (enables HTTPS with -tls-key)")
	tlsKey := flag.String("tls-key", "", "PEM private key for -tls-cert")
	flag.Parse()

	// One shared, resource-bounded Pool backs every request.
	pool := xcrack.NewPool(xcrack.Options{MaxProcs: 8})
	defer pool.Close()

	srv := api.NewServer(pool, api.Config{
		MaxBodyBytes:     128 << 20,
		RequestTimeout:   60 * time.Second,
		AllowDefaultList: true,
		// Per-request audit hook: emit one line per completed request, plus a
		// marker for each recovered node. Swap in your logger / SIEM here.
		Audit: func(res *xcrack.Result, meta api.AuditMeta) {
			log.Printf("request client=%s endpoint=%s bytes=%d elapsed=%s cracked=%v",
				meta.RemoteAddr, meta.Endpoint, meta.Bytes, meta.Elapsed.Round(time.Millisecond),
				len(res.Passwords()) > 0)
		},
	})

	// Mount the API under /crack/ alongside your own application's routes.
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprintln(w, "ok") })
	mux.Handle("/crack/", http.StripPrefix("/crack", srv.Handler()))

	httpSrv := &http.Server{Addr: *addr, Handler: mux, ReadTimeout: 30 * time.Second, WriteTimeout: 90 * time.Second}

	go func() {
		scheme := "http"
		var err error
		if *tlsCert != "" && *tlsKey != "" {
			scheme = "https"
			err = httpSrv.ListenAndServeTLS(*tlsCert, *tlsKey)
		} else {
			err = httpSrv.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			log.Fatalf("serve: %v", err)
		}
		_ = scheme
	}()
	log.Printf("xcrack HTTP service on %s (POST /crack/v1/decrypt, /crack/v1/identify)", *addr)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(ctx)
}
