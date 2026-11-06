package auth

import (
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestPasswordIPCapacityIPv6AndConcurrentBudget(t *testing.T) {
	g, e := newTrafficGate()
	if e != nil {
		t.Fatal(e)
	}
	now := time.Unix(2000000000, 0)
	for i := 0; i < 4096; i++ {
		addr := netip.AddrFrom4([4]byte{198, 18, byte(i >> 8), byte(i)})
		if !g.allow(addr.String(), now) {
			t.Fatal("early bounded-map denial")
		}
	}
	if len(g.ips) != 4096 || g.allow("192.0.2.1", now) {
		t.Fatal("unbounded IP map")
	}
	if !g.allow("192.0.2.1", now.Add(time.Minute)) {
		t.Fatal("expired-map capacity did not recover")
	}
	g, e = newTrafficGate()
	if e != nil {
		t.Fatal(e)
	}
	for range 30 {
		if !g.allow("2001:db8:1:2::1", now) {
			t.Fatal("early IPv6 denial")
		}
	}
	if g.allow("2001:db8:1:2::abcd", now) {
		t.Fatal("IPv6 host churn bypassed /64")
	}
	if !g.allow("2001:db8:1:3::1", now) {
		t.Fatal("independent IPv6 subnet denied")
	}
	for range 30 {
		if !g.allow("::ffff:192.0.2.1", now) {
			t.Fatal("early mapped IPv4 denial")
		}
	}
	if g.allow("192.0.2.1", now) {
		t.Fatal("IPv4 mapping bypassed bucket")
	}
	g, e = newTrafficGate()
	if e != nil {
		t.Fatal(e)
	}
	var accepted atomic.Int64
	var wg sync.WaitGroup
	for range 60 {
		wg.Go(func() {
			if g.allow("192.0.2.2", now) {
				accepted.Add(1)
			}
		})
	}
	wg.Wait()
	if accepted.Load() != 30 {
		t.Fatal("concurrent IP budget escaped ceiling")
	}
	if g.allow("192.0.2.2", now.Add(-time.Second)) {
		t.Fatal("clock rollback refilled IP budget")
	}
}
