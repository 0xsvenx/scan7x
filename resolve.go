package main

import (
	"context"
	"net"
	"sort"
	"sync"
	"time"
)

// ResolvedHost is a subdomain that resolves in DNS, with its IP addresses.
type ResolvedHost struct {
	Host string   `json:"host"`
	IPs  []string `json:"ips"`
}

// resolveHosts resolves each host concurrently and returns only the ones that
// resolve. Probing the resolvable subset avoids wasting time on dead names.
func resolveHosts(ctx context.Context, hosts []string, threads int) []ResolvedHost {
	if threads < 1 {
		threads = 1
	}
	resolver := &net.Resolver{}
	in := make(chan string)
	out := make(chan ResolvedHost)
	var wg sync.WaitGroup
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for h := range in {
				rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
				addrs, err := resolver.LookupHost(rctx, h)
				cancel()
				if err != nil || len(addrs) == 0 {
					continue
				}
				out <- ResolvedHost{Host: h, IPs: dedupSorted(addrs)}
			}
		}()
	}
	go func() {
		defer close(in)
		for _, h := range hosts {
			select {
			case <-ctx.Done():
				return
			case in <- h:
			}
		}
	}()
	go func() {
		wg.Wait()
		close(out)
	}()
	var res []ResolvedHost
	for r := range out {
		res = append(res, r)
	}
	sort.Slice(res, func(i, j int) bool { return res[i].Host < res[j].Host })
	return res
}
