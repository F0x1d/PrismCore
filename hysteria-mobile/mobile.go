// Package mobile provides a gomobile-compatible binding for Hysteria client
// with SOCKS5 proxy support.
package mobile

import (
	"errors"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/apernet/hysteria/core/v2/client"
	"github.com/apernet/hysteria/extras/v2/obfs"
	"github.com/apernet/hysteria/extras/v2/transport/udphop"
)

// ClientConfig holds all configuration for the Hysteria client.
// All fields are gomobile-safe primitive types.
type ClientConfig struct {
	// ServerAddress is the server address.
	// Supports port hopping syntax: "host:port", "host:port1-port2", "host:port1,port2,port3"
	ServerAddress string

	// Auth is the authentication token.
	Auth string

	// TLSServerName is the TLS SNI for the server.
	// If empty, the host part of ServerAddress is used.
	TLSServerName string

	// TLSInsecureSkipVerify disables TLS certificate verification.
	TLSInsecureSkipVerify bool

	// MaxTxBps is the maximum upload bandwidth in bytes per second.
	// 0 means auto (BBR).
	MaxTxBps int64

	// MaxRxBps is the maximum download bandwidth in bytes per second.
	// 0 means auto (BBR).
	MaxRxBps int64

	// Socks5Listen is the SOCKS5 listen address (e.g. "127.0.0.1:1080").
	Socks5Listen string

	// Socks5Username is the optional SOCKS5 authentication username.
	// Leave empty to disable SOCKS5 authentication.
	Socks5Username string

	// Socks5Password is the optional SOCKS5 authentication password.
	Socks5Password string

	// Socks5DisableUDP disables UDP support in the SOCKS5 server.
	Socks5DisableUDP bool

	// ObfsSalamander is the Salamander obfuscation password.
	// Leave empty to disable obfuscation.
	ObfsSalamander string

	// HopIntervalSec is the port hopping interval in seconds.
	// Only used when ServerAddress uses port hopping syntax.
	// 0 means default (30s). Minimum is 5s.
	HopIntervalSec int

	// FastOpen enables QUIC 0-RTT fast open.
	FastOpen bool

	// Lazy defers the connection until the first TCP/UDP request.
	Lazy bool
}

// EventHandler receives events from the Hysteria client.
// Implement this interface in your iOS app to receive callbacks.
type EventHandler interface {
	// OnConnected is called when the client connects to the server.
	OnConnected(count int)

	// OnSOCKS5TCPRequest is called when a SOCKS5 TCP request is made.
	OnSOCKS5TCPRequest(addr string, reqAddr string)

	// OnSOCKS5TCPError is called when a SOCKS5 TCP request fails.
	OnSOCKS5TCPError(addr string, reqAddr string, err string)

	// OnSOCKS5UDPRequest is called when a SOCKS5 UDP request is made.
	OnSOCKS5UDPRequest(addr string)

	// OnSOCKS5UDPError is called when a SOCKS5 UDP request fails.
	OnSOCKS5UDPError(addr string, err string)
}

// HysteriaClient wraps the Hysteria client and SOCKS5 server.
type HysteriaClient struct {
	config   *ClientConfig
	handler  EventHandler
	hyClient client.Client
	listener net.Listener
	mu       sync.Mutex
	running  bool
}

// NewClient creates a new HysteriaClient.
// handler can be nil if you don't need event callbacks.
func NewClient(config *ClientConfig, handler EventHandler) *HysteriaClient {
	return &HysteriaClient{
		config:  config,
		handler: handler,
	}
}

// Start connects to the server and starts the SOCKS5 proxy.
func (c *HysteriaClient) Start() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.running {
		return errors.New("client is already running")
	}

	// Resolve server address
	serverAddr, isHop, err := resolveServerAddr(c.config.ServerAddress)
	if err != nil {
		return err
	}

	// Determine TLS server name
	tlsServerName := c.config.TLSServerName
	if tlsServerName == "" {
		host, _, err := net.SplitHostPort(c.config.ServerAddress)
		if err != nil {
			// If port hopping, the "port" part may not parse normally.
			// Try to get host anyway.
			tlsServerName = c.config.ServerAddress
		} else {
			tlsServerName = host
		}
	}

	// Build obfuscator
	var obfuscator obfs.Obfuscator
	if c.config.ObfsSalamander != "" {
		ob, err := obfs.NewSalamanderObfuscator([]byte(c.config.ObfsSalamander))
		if err != nil {
			return err
		}
		obfuscator = ob
	}

	// Build ConnFactory
	hopInterval := time.Duration(c.config.HopIntervalSec) * time.Second
	connFactory := &adaptiveConnFactory{
		isHop:       isHop,
		hopInterval: hopInterval,
		obfuscator:  obfuscator,
	}
	if isHop {
		connFactory.hopAddr = serverAddr.(*udphop.UDPHopAddr)
	}

	handler := c.handler

	// Build core config via a function (for reconnectable client DNS re-resolution)
	configFunc := func() (*client.Config, error) {
		addr, _, err := resolveServerAddr(c.config.ServerAddress)
		if err != nil {
			return nil, err
		}
		return &client.Config{
			ConnFactory: connFactory,
			ServerAddr:  addr,
			Auth:        c.config.Auth,
			TLSConfig: client.TLSConfig{
				ServerName:         tlsServerName,
				InsecureSkipVerify: c.config.TLSInsecureSkipVerify,
			},
			BandwidthConfig: client.BandwidthConfig{
				MaxTx: uint64(c.config.MaxTxBps),
				MaxRx: uint64(c.config.MaxRxBps),
			},
			FastOpen: c.config.FastOpen,
		}, nil
	}

	connectedFunc := func(_ client.Client, _ *client.HandshakeInfo, count int) {
		if handler != nil {
			handler.OnConnected(count)
		}
	}

	// Create reconnectable client
	hyClient, err := client.NewReconnectableClient(configFunc, connectedFunc, c.config.Lazy)
	if err != nil {
		return err
	}
	c.hyClient = hyClient

	// Start SOCKS5 listener
	listener, err := net.Listen("tcp", c.config.Socks5Listen)
	if err != nil {
		_ = hyClient.Close()
		c.hyClient = nil
		return err
	}
	c.listener = listener

	// Build SOCKS5 server
	s := &socks5Server{
		hyClient:   hyClient,
		disableUDP: c.config.Socks5DisableUDP,
	}

	// Set auth if configured
	if c.config.Socks5Username != "" || c.config.Socks5Password != "" {
		username := c.config.Socks5Username
		password := c.config.Socks5Password
		s.authFunc = func(u, p string) bool {
			return u == username && p == password
		}
	}

	// Set event logger
	if handler != nil {
		s.eventLogger = &mobileEventLogger{handler: handler}
	}

	c.running = true

	// Run SOCKS5 server in background
	go func() {
		_ = s.serve(listener)
		c.mu.Lock()
		c.running = false
		c.mu.Unlock()
	}()

	return nil
}

// Stop shuts down the SOCKS5 server and disconnects the client.
func (c *HysteriaClient) Stop() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.running {
		return errors.New("client is not running")
	}

	var firstErr error
	if c.listener != nil {
		if err := c.listener.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		c.listener = nil
	}
	if c.hyClient != nil {
		if err := c.hyClient.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		c.hyClient = nil
	}

	c.running = false
	return firstErr
}

// IsRunning returns whether the client is currently running.
func (c *HysteriaClient) IsRunning() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.running
}

// resolveServerAddr parses the server address string and returns the resolved address.
// Returns (addr, isPortHopping, error).
func resolveServerAddr(addrStr string) (net.Addr, bool, error) {
	host, port, err := net.SplitHostPort(addrStr)
	if err != nil {
		return nil, false, err
	}
	_ = host

	if isPortHoppingPort(port) {
		addr, err := udphop.ResolveUDPHopAddr(addrStr)
		if err != nil {
			return nil, false, err
		}
		return addr, true, nil
	}

	addr, err := net.ResolveUDPAddr("udp", addrStr)
	if err != nil {
		return nil, false, err
	}
	return addr, false, nil
}

func isPortHoppingPort(port string) bool {
	return strings.Contains(port, "-") || strings.Contains(port, ",")
}

// adaptiveConnFactory creates net.PacketConn with optional obfuscation and port hopping.
type adaptiveConnFactory struct {
	isHop       bool
	hopAddr     *udphop.UDPHopAddr
	hopInterval time.Duration
	obfuscator  obfs.Obfuscator
}

func (f *adaptiveConnFactory) New(addr net.Addr) (net.PacketConn, error) {
	var conn net.PacketConn
	var err error

	if f.isHop {
		hopAddr, ok := addr.(*udphop.UDPHopAddr)
		if !ok {
			// Use the factory's stored hopAddr as fallback
			hopAddr = f.hopAddr
		}
		conn, err = udphop.NewUDPHopPacketConn(hopAddr, f.hopInterval, nil)
	} else {
		conn, err = net.ListenUDP("udp", nil)
	}

	if err != nil {
		return nil, err
	}

	if f.obfuscator != nil {
		conn = obfs.WrapPacketConn(conn, f.obfuscator)
	}

	return conn, nil
}

// mobileEventLogger adapts EventHandler to the SOCKS5 event logger interface.
type mobileEventLogger struct {
	handler EventHandler
}

func (l *mobileEventLogger) TCPRequest(addr net.Addr, reqAddr string) {
	l.handler.OnSOCKS5TCPRequest(addr.String(), reqAddr)
}

func (l *mobileEventLogger) TCPError(addr net.Addr, reqAddr string, err error) {
	errStr := ""
	if err != nil {
		errStr = err.Error()
	}
	l.handler.OnSOCKS5TCPError(addr.String(), reqAddr, errStr)
}

func (l *mobileEventLogger) UDPRequest(addr net.Addr) {
	l.handler.OnSOCKS5UDPRequest(addr.String())
}

func (l *mobileEventLogger) UDPError(addr net.Addr, err error) {
	errStr := ""
	if err != nil {
		errStr = err.Error()
	}
	l.handler.OnSOCKS5UDPError(addr.String(), errStr)
}
