// SPDX-License-Identifier: GPL-3.0-only

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

// models stores the extracted model name per inbound request.
// Set in Rewrite (keyed by pr.In), read+deleted in the mux handler.
var models sync.Map

// responseRecorder wraps http.ResponseWriter to capture status code and
// response body size for audit logging. Implements Unwrap so
// http.ResponseController (used by ReverseProxy for SSE flushing) can
// find the real Flusher/Hijacker on the underlying writer.
type responseRecorder struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (r *responseRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

func (r *responseRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *responseRecorder) Write(b []byte) (int, error) {
	n, err := r.ResponseWriter.Write(b)
	r.bytes += int64(n)
	return n, err
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "proxy: "+format+"\n", args...)
	os.Exit(1)
}

func main() {
	upstream, err := url.Parse(requireEnv("PROXY_UPSTREAM"))
	if err != nil {
		fatalf("bad PROXY_UPSTREAM: %v", err)
	}
	port := requireEnv("PROXY_PORT")
	headerName := requireEnv("PROXY_HEADER_NAME")
	headerPrefix := os.Getenv("PROXY_HEADER_PREFIX") // may be empty
	keyValue := requireEnv("PROXY_KEY")

	proxy := &httputil.ReverseProxy{
		FlushInterval: -1, // immediate flush for SSE streaming
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(upstream)
			pr.Out.Host = upstream.Host
			pr.Out.Header.Del(headerName)
			pr.Out.Header.Set(headerName, headerPrefix+keyValue)

			// Buffer the request body so the HTTP/2 transport can
			// retry after receiving a GOAWAY frame from upstream.
			// Without GetBody, the transport cannot re-read the body
			// and returns an error to the client instead of retrying.
			if pr.Out.Body != nil && pr.Out.GetBody == nil {
				body, err := io.ReadAll(pr.Out.Body)
				pr.Out.Body.Close()
				if err != nil {
					return
				}
				pr.Out.Body = io.NopCloser(bytes.NewReader(body))
				pr.Out.GetBody = func() (io.ReadCloser, error) {
					return io.NopCloser(bytes.NewReader(body)), nil
				}
				pr.Out.ContentLength = int64(len(body))

				// Extract model name for audit logging.
				var partial struct{ Model string }
				if json.Unmarshal(body, &partial) == nil && partial.Model != "" {
					models.Store(pr.In, partial.Model)
				}
			}
		},
	}

	proxy.ErrorHandler = func(w http.ResponseWriter, req *http.Request, err error) {
		fmt.Fprintf(os.Stderr, "proxy: %s %s %s %s error: %v\n",
			time.Now().UTC().Format(time.RFC3339), req.RemoteAddr,
			req.Method, req.URL.Path, err)
		w.WriteHeader(http.StatusBadGateway)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		start := time.Now().UTC()
		rec := &responseRecorder{ResponseWriter: w, status: http.StatusOK}
		proxy.ServeHTTP(rec, req)
		model, _ := models.LoadAndDelete(req)
		modelStr, _ := model.(string)
		if modelStr == "" {
			modelStr = modelFromPath(req.URL.Path)
		}
		fmt.Fprintf(os.Stderr, "clampdown: %s proxy: %s %s %d model=%s req=%d resp=%d %s\n",
			start.Format(time.RFC3339),
			req.Method, req.URL.Path, rec.status, modelStr,
			req.ContentLength, rec.bytes,
			time.Since(start).Truncate(time.Millisecond))
	})

	addr := "127.0.0.1:" + port
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		fatalf("listen %s: %v", addr, err)
	}

	srv := &http.Server{Handler: mux}
	go func() {
		err := srv.Serve(ln)
		if err != nil && err != http.ErrServerClosed {
			fatalf("serve %s: %v", addr, err)
		}
	}()

	fmt.Fprintf(os.Stderr, "proxy: %s %s -> %s\n", time.Now().UTC().Format(time.RFC3339), addr, upstream)
	fmt.Fprintf(os.Stderr, "proxy: %s ready\n", time.Now().UTC().Format(time.RFC3339))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
}

// modelFromPath extracts the model from Gemini-style URL paths
// like /v1beta/models/gemini-pro:generateContent. Returns "-" if
// the path doesn't match.
func modelFromPath(path string) string {
	const prefix = "/models/"
	i := strings.Index(path, prefix)
	if i < 0 {
		return "-"
	}
	rest := path[i+len(prefix):]
	if rest == "" {
		return "-"
	}
	colon := strings.IndexByte(rest, ':')
	if colon > 0 {
		return rest[:colon]
	}
	return rest
}

func requireEnv(name string) string {
	v := os.Getenv(name)
	if v == "" {
		fatalf("%s not set", name)
	}
	return v
}
