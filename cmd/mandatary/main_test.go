package main

import (
	"testing"
	"time"
)

func TestDevelopmentServerHasBoundedIOAndStaticOnlySurface(t *testing.T) {
	s := developmentServer()
	if s.Addr != "127.0.0.1:8080" {
		t.Fatalf("development server must bind loopback: %s", s.Addr)
	}
	if s.ReadHeaderTimeout != 5*time.Second || s.ReadTimeout != 10*time.Second || s.WriteTimeout != 10*time.Second || s.IdleTimeout != 60*time.Second {
		t.Fatal("missing bounded HTTP I/O")
	}
	if s.Handler == nil || s.MaxHeaderBytes != 16*1024 {
		t.Fatal("server missing static handler/header bound")
	}
}
