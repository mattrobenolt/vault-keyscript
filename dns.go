package main

import (
	"fmt"
	"net"
	"net/url"

	"github.com/miekg/dns"
)

// Explicit list of DNS resolvers.
var DNS_RESOLVERS = [...]string{
	// Google
	"8.8.8.8:53", "8.8.4.4:53",
	// OpenDNS
	"208.67.222.222:53", "208.67.220.220:53",
}

// Take a full url as input, and resolve it to IP/Host pair.
func resolveURL(addr string) (string, string, error) {
	u, err := url.Parse(addr)
	if err != nil {
		return "", "", err
	}

	// split apart host:port pair so we can work with just host
	host, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		host = u.Host
		port = ""
	}

	// check if the hostname is already an IP address, or if it
	// needs to actually be resolved
	if ip := net.ParseIP(host); ip == nil {
		host, err = resolveHost(host)
		if err != nil {
			return "", "", err
		}
	}

	// Save a reference for the actual Host needed in the header
	serverName := u.Host
	u.Host = net.JoinHostPort(host, port)

	return u.String(), serverName, nil
}

// Take a hostname, and attempt to give us back the first
// A record that can be resolved.
func resolveHost(hostname string) (string, error) {
	var client dns.Client
	var m dns.Msg

	for _, server := range DNS_RESOLVERS {
		m.SetQuestion(hostname+".", dns.TypeA)
		r, _, err := client.Exchange(&m, server)
		if err != nil {
			// we failed, so just move on to the next resolver
			continue
		}

		// Return the first A record we find
		for _, answer := range r.Answer {
			if record, ok := answer.(*dns.A); ok {
				return record.A.String(), nil
			}
		}
	}

	return "", fmt.Errorf("cannot resolve IP address")
}
