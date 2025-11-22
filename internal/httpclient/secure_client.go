package httpclient

import (
	"context"
	"errors"
	"net"
	"net/http"
	"time"
)

// SecureClient wraps http.Client with SSRF protections (no private IPs) and timeouts.
type SecureClient struct {
	Client       *http.Client
	Timeout      time.Duration
	Resolver     net.Resolver
	AllowedCIDRs []*net.IPNet
}

// New returns a SecureClient with sane defaults disallowing private/local ranges.
func New() *SecureClient {
	private := mustCIDRs([]string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"::1/128",
		"fc00::/7",
		"fe80::/10",
	})
	return &SecureClient{
		Client:       &http.Client{},
		Timeout:      5 * time.Second,
		Resolver:     net.Resolver{},
		AllowedCIDRs: private,
	}
}

// Do issues the request after checking host resolution.
func (c *SecureClient) Do(req *http.Request) (*http.Response, error) {
	if err := c.checkHost(req.Context(), req.URL.Hostname()); err != nil {
		return nil, err
	}
	client := c.Client
	if client == nil {
		client = http.DefaultClient
	}
	if c.Timeout > 0 {
		ctx, cancel := context.WithTimeout(req.Context(), c.Timeout)
		defer cancel()
		req = req.Clone(ctx)
	}
	return client.Do(req)
}

func (c *SecureClient) checkHost(ctx context.Context, host string) error {
	addrs, err := c.Resolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return err
	}
	for _, ip := range addrs {
		for _, cidr := range c.AllowedCIDRs {
			if cidr.Contains(ip) {
				return errors.New("blocked private address")
			}
		}
	}
	return nil
}

func mustCIDRs(cidrs []string) []*net.IPNet {
	var nets []*net.IPNet
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err == nil {
			nets = append(nets, n)
		}
	}
	return nets
}
