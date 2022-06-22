package gomitmproxy

import (
	"crypto/tls"
	"net"
	"net/http"
	"time"

	"github.com/chaudhryfaisal/gomitmproxy/mitm"
)

// Config is the configuration of the Proxy
type Config struct {
	Timeout             time.Duration // Timeout
	TLSHandshakeTimeout time.Duration // TLSHandshakeTimeout
	DialKeepAlive       time.Duration // DialKeepAlive
	DialTimeout         time.Duration // DialTimeout
	TLSClientConfig     *tls.Config   // TLSClientConfig

	ListenAddr *net.TCPAddr // Address to listen to

	// TLSConfig is a config to use for the HTTP over TLS proxy
	// If not set, gomitmproxy will work as a simple plain HTTP proxy
	TLSConfig *tls.Config

	// Username for Proxy-Authorization
	Username string
	// Password for Proxy-Authorization
	Password string

	MITMConfig     *mitm.Config // If not nil, MITM is enabled for the proxy
	MITMExceptions []string     // A list of hostnames for which MITM will be disabled

	// APIHost is a name of the gomitmproxy API
	// If it is set to "", there will be no API
	// Here are the methods exposed:
	// 1. apihost/cert.crt -- serves the authority cert (if MITMConfig is configured)
	APIHost string

	// OnConnect is called when the proxy tries to open a net.Conn.
	// It allows you to hijack the remote connection and replace it with your own.
	//
	// 1. When the proxy handles the HTTP CONNECT.
	//    IMPORTANT: In this case we don't actually use the remote connections.
	//    It is only used to check if the remote endpoint is available
	// 2. When the proxy bypasses data from the client to the remote endpoint.
	//    For instance, it could happen when there's a WebSocket connection.
	OnConnect func(session *Session, proto string, addr string) net.Conn

	// OnRequest is called when the request has been just received,
	// but has not been sent to the remote server.
	//
	// At this stage, it is possible to do the following things:
	// 1. Modify or even replace the request
	// 2. Supply an HTTP response to be written to the client
	//
	// Return nil instead of *http.Request or *http.Response to keep
	// the original request / response
	//
	// Note that even if you supply your own HTTP response here,
	// the OnResponse handler will be called anyway!
	OnRequest func(session *Session) (*http.Request, *http.Response)

	// OnResponse is called when the response has been just received,
	// but has not been sent to the local client.
	//
	// At this stage you can either keep the original response,
	// or you can replace it with a new one.
	OnResponse func(session *Session) *http.Response

	// OnError is called if there's an issue with retrieving
	// the response from the remote server.
	OnError func(session *Session, err error)
}

func (c *Config) UpdateDefaults() {
	if c.Timeout.Seconds() == 0 {
		c.Timeout = defaultTimeout
	}
	if c.TLSHandshakeTimeout.Seconds() == 0 {
		c.TLSHandshakeTimeout = defaultTLSHandshakeTimeout
	}
	if c.DialTimeout.Seconds() == 0 {
		c.DialTimeout = dialTimeout
	}
	if c.DialKeepAlive.Seconds() == 0 {
		c.DialKeepAlive = dialTimeout
	}
	if c.TLSClientConfig == nil {
		c.TLSClientConfig = DefaultTLSClientConfig()
	}
}

func DefaultTLSClientConfig() *tls.Config {
	return &tls.Config{
		GetClientCertificate: func(info *tls.CertificateRequestInfo) (certificate *tls.Certificate, e error) {
			// We purposefully cause an error here so that the http.Transport.RoundTrip method failed
			// In this case we'll receive the error and will be able to add the host to invalidTLSHosts
			return nil, errClientCertRequested
		},
	}
}
