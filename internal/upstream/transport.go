package upstream

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	xproxy "golang.org/x/net/proxy"
)

type dialContextFunc func(ctx context.Context, network, addr string) (net.Conn, error)

type cachedTransport struct {
	proxyURL  string
	transport *http.Transport
	dialCtx   dialContextFunc
}

func buildTransport(rawProxy string) (*http.Transport, dialContextFunc, error) {
	baseDialer := &net.Dialer{
		Timeout:   20 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	trimmed := strings.TrimSpace(rawProxy)
	if trimmed == "" {
		tr := &http.Transport{
			Proxy:                 nil,
			DialContext:           baseDialer.DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          64,
			MaxIdleConnsPerHost:   16,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   15 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		}
		return tr, baseDialer.DialContext, nil
	}

	u, err := url.Parse(trimmed)
	if err != nil || u.Host == "" {
		return nil, nil, fmt.Errorf("invalid upstream.proxy_url")
	}
	scheme := strings.ToLower(u.Scheme)
	switch scheme {
	case "http", "https":
		dialFn := makeHTTPConnectDialer(u, baseDialer)
		tr := &http.Transport{
			Proxy:                 http.ProxyURL(u),
			DialContext:           baseDialer.DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          64,
			MaxIdleConnsPerHost:   16,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   15 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		}
		return tr, dialFn, nil

	case "socks5", "socks5h":
		var auth *xproxy.Auth
		if u.User != nil {
			pw, _ := u.User.Password()
			auth = &xproxy.Auth{
				User:     u.User.Username(),
				Password: pw,
			}
		}
		d, derr := xproxy.SOCKS5("tcp", u.Host, auth, baseDialer)
		if derr != nil {
			return nil, nil, fmt.Errorf("configure socks5 proxy: %w", derr)
		}
		dialFn := dialContextFunc(func(ctx context.Context, network, addr string) (net.Conn, error) {
			if cd, ok := d.(xproxy.ContextDialer); ok {
				return cd.DialContext(ctx, network, addr)
			}
			type res struct {
				c   net.Conn
				err error
			}
			ch := make(chan res, 1)
			go func() {
				c, err := d.Dial(network, addr)
				ch <- res{c, err}
			}()
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case r := <-ch:
				return r.c, r.err
			}
		})
		tr := &http.Transport{
			Proxy:                 nil,
			DialContext:           dialFn,
			ForceAttemptHTTP2:     false,
			MaxIdleConns:          64,
			MaxIdleConnsPerHost:   16,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   15 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		}
		return tr, dialFn, nil

	default:
		return nil, nil, fmt.Errorf("unsupported upstream.proxy_url scheme %q", scheme)
	}
}

func makeHTTPConnectDialer(proxyURL *url.URL, base *net.Dialer) dialContextFunc {
	proxyAddr := proxyURL.Host
	if proxyURL.Port() == "" {
		if strings.EqualFold(proxyURL.Scheme, "https") {
			proxyAddr = net.JoinHostPort(proxyURL.Hostname(), "443")
		} else {
			proxyAddr = net.JoinHostPort(proxyURL.Hostname(), "80")
		}
	}
	var authHeader string
	if proxyURL.User != nil {
		pw, _ := proxyURL.User.Password()
		token := base64.StdEncoding.EncodeToString([]byte(proxyURL.User.Username() + ":" + pw))
		authHeader = "Basic " + token
	}
	useTLS := strings.EqualFold(proxyURL.Scheme, "https")
	tlsHost := proxyURL.Hostname()

	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := base.DialContext(ctx, "tcp", proxyAddr)
		if err != nil {
			return nil, err
		}
		if useTLS {
			tlsConn := tls.Client(conn, &tls.Config{
				ServerName: tlsHost,
				MinVersion: tls.VersionTLS12,
			})
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				_ = conn.Close()
				return nil, err
			}
			conn = tlsConn
		}
		if dl, ok := ctx.Deadline(); ok {
			_ = conn.SetDeadline(dl)
			defer conn.SetDeadline(time.Time{})
		}
		req := &http.Request{
			Method: http.MethodConnect,
			URL:    &url.URL{Opaque: addr},
			Host:   addr,
			Header: make(http.Header),
		}
		if authHeader != "" {
			req.Header.Set("Proxy-Authorization", authHeader)
		}
		if err := req.Write(conn); err != nil {
			_ = conn.Close()
			return nil, err
		}
		br := bufio.NewReader(conn)
		resp, err := http.ReadResponse(br, req)
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			_ = conn.Close()
			return nil, fmt.Errorf("proxy CONNECT returned HTTP %d", resp.StatusCode)
		}
		return conn, nil
	}
}

func (c *Client) transportAndDialer() (*http.Transport, dialContextFunc, error) {
	proxyURL := strings.TrimSpace(c.Config().ProxyURL)
	c.trMu.Lock()
	defer c.trMu.Unlock()
	if c.trCache != nil && c.trCache.proxyURL == proxyURL {
		return c.trCache.transport, c.trCache.dialCtx, nil
	}
	tr, dialFn, err := buildTransport(proxyURL)
	if err != nil {
		return nil, nil, err
	}
	if c.trCache != nil && c.trCache.transport != nil {
		c.trCache.transport.CloseIdleConnections()
	}
	c.trCache = &cachedTransport{
		proxyURL:  proxyURL,
		transport: tr,
		dialCtx:   dialFn,
	}
	return tr, dialFn, nil
}

// HTTPClient returns an *http.Client configured with the single optional upstream.proxy_url.
// Falls back to a direct client if the configured proxy URL is invalid.
func (c *Client) HTTPClient(timeout time.Duration) *http.Client {
	tr, _, err := c.transportAndDialer()
	if err != nil {
		return &http.Client{Timeout: timeout}
	}
	return &http.Client{
		Transport: tr,
		Timeout:   timeout,
	}
}

func (c *Client) upstreamHTTPClient(timeout time.Duration) (*http.Client, error) {
	tr, _, err := c.transportAndDialer()
	if err != nil {
		return nil, &UpstreamError{Kind: ErrKindTransport, StatusCode: 502, Message: "代理配置无效: " + err.Error()}
	}
	return &http.Client{
		Transport: tr,
		Timeout:   timeout,
	}, nil
}
