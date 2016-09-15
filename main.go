package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/certifi/gocertifi"
	"github.com/miekg/dns"
)

// Explicit list of DNS resolvers.
var DNS_RESOLVERS = []string{
	// Google
	"8.8.8.8:53", "8.8.4.4:53",
	// OpenDNS
	"208.67.222.222:53", "208.67.220.220:53",
}

type ClientConfig struct {
	vaultAddr string
	roleId    string
	uuid      string
	hostname  string
	token     string // Auth token, should not be set manually
}

type Client struct {
	config *ClientConfig
	client *http.Client
	host   string // Actual Host header for HTTP requests
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
	hostHeader := u.Host
	u.Host = net.JoinHostPort(host, port)

	return u.String(), hostHeader, nil
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

// Take input in the form:
// 	key1=value;key2=value
func splitArgs(args string, sep string) map[string]string {
	m := make(map[string]string)
	for _, bit := range strings.Split(args, sep) {
		pair := strings.SplitN(bit, "=", 2)
		m[pair[0]] = pair[1]
	}
	return m
}

func maybeWups(err error) {
	if err != nil {
		wups(err)
	}
}

func wups(v interface{}) {
	fmt.Fprintf(os.Stderr, "!! %s\n", v)
	os.Exit(1)
}

// Initialize a new API client for interacting with Vault
func newClient(args string) *Client {
	m := splitArgs(args, ";")

	// Load in our root certificates via certifi
	// so we don't rely on the OS certificates existing
	rootCerts, err := gocertifi.CACerts()
	maybeWups(err)

	// Now we need to manually resolve our vault address
	// back into an IP/Host combo. This is done becasue
	// we can't rely on /etc/resolv.conf existing, which means
	// we can't leverage the normal DNS resolution that Go
	// would do for us, nor can we leverage glibc here since
	// it's possible it can't resolve either. So we are
	// opting to do this in pure Go and do this ourselves
	// to avoid the issue entirely.
	vaultAddr, hostHeader, err := resolveURL(m["vault_addr"])
	maybeWups(err)

	return &Client{
		config: &ClientConfig{
			roleId:    m["role_id"],
			uuid:      m["uuid"],
			hostname:  m["hostname"],
			vaultAddr: vaultAddr,
			token:     "",
		},
		// Create custom http.Client that has our root certificates bound to it
		client: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{RootCAs: rootCerts},
			},
		},
		host: hostHeader,
	}
}

// Make an HTTP request to Vault server while binding correct HTTP headers
func (c *Client) request(method, path string, body []byte) (*http.Response, error) {
	req, err := http.NewRequest(method, fmt.Sprintf("%s/v1/%s", c.config.vaultAddr, path), bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}
	// Bind back correct Host for use with Host header
	req.Host = c.host
	req.Header.Add("Host", c.host)

	if c.config.token != "" {
		req.Header.Add("X-Vault-Token", c.config.token)
	}
	return c.client.Do(req)
}

// Exchange role_id for an auth token
func (c *Client) login() {
	body := []byte(fmt.Sprintf(`{"role_id":"%s"}`, c.config.roleId))
	resp, err := c.request("POST", "auth/approle/login", body)
	maybeWups(err)
	defer resp.Body.Close()
	body, err = ioutil.ReadAll(resp.Body)
	maybeWups(err)

	var p struct {
		Errors []string
		Auth   struct {
			ClientToken string `json:"client_token"`
		}
	}
	if err := json.Unmarshal(body, &p); err != nil {
		wups(err)
	}
	if len(p.Errors) > 0 {
		wups(p.Errors[0])
	}
	c.config.token = p.Auth.ClientToken
}

func (c *Client) getKey() string {
	c.login()

	resp, err := c.request("GET", fmt.Sprintf("secret/disk/%s", c.config.hostname), nil)
	maybeWups(err)
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	maybeWups(err)

	var p struct {
		Errors []string
		Data   map[string]string
	}
	if err := json.Unmarshal(body, &p); err != nil {
		wups(err)
	}
	if len(p.Errors) > 0 {
		wups(p.Errors[0])
	}
	key, ok := p.Data[c.config.uuid]
	if !ok {
		wups("unknown uuid")
	}
	return key
}

func main() {
	if len(os.Args) != 2 {
		wups("Exactly one argument expected")
	}
	fmt.Print(newClient(os.Args[1]).getKey())
}
