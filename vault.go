package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/certifi/gocertifi"
)

type clientConfig struct {
	vaultAddr string
	roleId    string
	uuid      string
	hostname  string
	token     string // Auth token, should not be set manually
}

type Client struct {
	config     *clientConfig
	client     *http.Client
	serverName string // Actual Host header for HTTP requests
}

// Initialize a new API client for interacting with Vault
func newVaultClient(args string) *Client {
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
	vaultAddr, serverName, err := resolveURL(m.Get("vault_addr"))
	maybeWups(err)

	return &Client{
		config: &clientConfig{
			roleId:    m.Get("role_id"),
			uuid:      m.Get("uuid"),
			hostname:  m.Get("hostname"),
			vaultAddr: vaultAddr,
			token:     "",
		},
		// Create custom http.Client that has our root certificates bound to it
		client: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs:    rootCerts,
					ServerName: serverName,
				},
			},
		},
		serverName: serverName,
	}
}

// Make an HTTP request to Vault server while binding correct HTTP headers
func (c *Client) request(method, path string, body []byte) (*http.Response, error) {
	req, err := http.NewRequest(method, fmt.Sprintf("%s/v1/%s", c.config.vaultAddr, path), bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}
	// Bind back correct Host for use with Host header
	req.Host = c.serverName
	req.Header.Add("Host", c.serverName)

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
