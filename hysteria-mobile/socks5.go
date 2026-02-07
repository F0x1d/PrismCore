package mobile

import (
	"encoding/binary"
	"io"
	"net"

	"github.com/txthinking/socks5"

	"github.com/apernet/hysteria/core/v2/client"
)

const socks5UDPBufferSize = 4096

// socks5Server is a SOCKS5 server using a Hysteria client as outbound.
// Adapted from app/internal/socks5/server.go
type socks5Server struct {
	hyClient    client.Client
	authFunc    func(username, password string) bool // nil = no authentication
	disableUDP  bool
	eventLogger socks5EventLogger
}

type socks5EventLogger interface {
	TCPRequest(addr net.Addr, reqAddr string)
	TCPError(addr net.Addr, reqAddr string, err error)
	UDPRequest(addr net.Addr)
	UDPError(addr net.Addr, err error)
}

func (s *socks5Server) serve(listener net.Listener) error {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		go s.dispatch(conn)
	}
}

func (s *socks5Server) dispatch(conn net.Conn) {
	ok, _ := s.negotiate(conn)
	if !ok {
		_ = conn.Close()
		return
	}
	req, err := socks5.NewRequestFrom(conn)
	if err != nil {
		_ = conn.Close()
		return
	}
	switch req.Cmd {
	case socks5.CmdConnect:
		s.handleTCP(conn, req)
	case socks5.CmdUDP:
		if s.disableUDP {
			_ = s5SendSimpleReply(conn, socks5.RepCommandNotSupported)
			_ = conn.Close()
			return
		}
		s.handleUDP(conn, req)
	default:
		_ = s5SendSimpleReply(conn, socks5.RepCommandNotSupported)
		_ = conn.Close()
	}
}

func (s *socks5Server) negotiate(conn net.Conn) (bool, error) {
	req, err := socks5.NewNegotiationRequestFrom(conn)
	if err != nil {
		return false, err
	}
	var serverMethod byte
	if s.authFunc != nil {
		serverMethod = socks5.MethodUsernamePassword
	} else {
		serverMethod = socks5.MethodNone
	}
	supported := false
	for _, m := range req.Methods {
		if m == serverMethod {
			supported = true
			break
		}
	}
	if !supported {
		rep := socks5.NewNegotiationReply(socks5.MethodUnsupportAll)
		_, err := rep.WriteTo(conn)
		return false, err
	}
	rep := socks5.NewNegotiationReply(serverMethod)
	_, err = rep.WriteTo(conn)
	if err != nil {
		return false, err
	}
	if serverMethod == socks5.MethodUsernamePassword {
		req, err := socks5.NewUserPassNegotiationRequestFrom(conn)
		if err != nil {
			return false, err
		}
		ok := s.authFunc(string(req.Uname), string(req.Passwd))
		if ok {
			rep := socks5.NewUserPassNegotiationReply(socks5.UserPassStatusSuccess)
			_, err := rep.WriteTo(conn)
			if err != nil {
				return false, err
			}
		} else {
			rep := socks5.NewUserPassNegotiationReply(socks5.UserPassStatusFailure)
			_, err := rep.WriteTo(conn)
			return false, err
		}
	}
	return true, nil
}

func (s *socks5Server) handleTCP(conn net.Conn, req *socks5.Request) {
	defer conn.Close()

	addr := req.Address()

	if s.eventLogger != nil {
		s.eventLogger.TCPRequest(conn.RemoteAddr(), addr)
	}
	var closeErr error
	defer func() {
		if s.eventLogger != nil {
			s.eventLogger.TCPError(conn.RemoteAddr(), addr, closeErr)
		}
	}()

	rConn, err := s.hyClient.TCP(addr)
	if err != nil {
		_ = s5SendSimpleReply(conn, socks5.RepHostUnreachable)
		closeErr = err
		return
	}
	defer rConn.Close()

	_ = s5SendSimpleReply(conn, socks5.RepSuccess)
	copyErrChan := make(chan error, 2)
	go func() {
		_, err := io.Copy(rConn, conn)
		copyErrChan <- err
	}()
	go func() {
		_, err := io.Copy(conn, rConn)
		copyErrChan <- err
	}()
	closeErr = <-copyErrChan
}

func (s *socks5Server) handleUDP(conn net.Conn, req *socks5.Request) {
	defer conn.Close()

	if s.eventLogger != nil {
		s.eventLogger.UDPRequest(conn.RemoteAddr())
	}
	var closeErr error
	defer func() {
		if s.eventLogger != nil {
			s.eventLogger.UDPError(conn.RemoteAddr(), closeErr)
		}
	}()

	host, _, err := net.SplitHostPort(conn.LocalAddr().String())
	if err != nil {
		_ = s5SendSimpleReply(conn, socks5.RepServerFailure)
		closeErr = err
		return
	}
	udpAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, "0"))
	if err != nil {
		_ = s5SendSimpleReply(conn, socks5.RepServerFailure)
		closeErr = err
		return
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		_ = s5SendSimpleReply(conn, socks5.RepServerFailure)
		closeErr = err
		return
	}
	defer udpConn.Close()

	hyUDP, err := s.hyClient.UDP()
	if err != nil {
		_ = s5SendSimpleReply(conn, socks5.RepServerFailure)
		closeErr = err
		return
	}
	defer hyUDP.Close()

	_ = s5SendUDPReply(conn, udpConn.LocalAddr().(*net.UDPAddr))

	errChan := make(chan error, 2)
	go func() {
		err := s.udpRelay(udpConn, hyUDP)
		errChan <- err
	}()
	go func() {
		_, err := io.Copy(io.Discard, conn)
		errChan <- err
	}()
	closeErr = <-errChan
}

func (s *socks5Server) udpRelay(udpConn *net.UDPConn, hyUDP client.HyUDPConn) error {
	var clientAddr *net.UDPAddr
	buf := make([]byte, socks5UDPBufferSize)
	for {
		n, cAddr, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			return err
		}
		d, err := socks5.NewDatagramFromBytes(buf[:n])
		if err != nil || d.Frag != 0 {
			continue
		}
		if clientAddr == nil {
			clientAddr = cAddr
			go func() {
				for {
					bs, from, err := hyUDP.Receive()
					if err != nil {
						_ = udpConn.Close()
						return
					}
					atyp, addr, port, err := socks5.ParseAddress(from)
					if err != nil {
						continue
					}
					if atyp == socks5.ATYPDomain {
						addr = addr[1:]
					}
					d := socks5.NewDatagram(atyp, addr, port, bs)
					_, _ = udpConn.WriteToUDP(d.Bytes(), clientAddr)
				}
			}()
		} else if !clientAddr.IP.Equal(cAddr.IP) || clientAddr.Port != cAddr.Port {
			continue
		}
		_ = hyUDP.Send(d.Data, d.Address())
	}
}

func s5SendSimpleReply(conn net.Conn, rep byte) error {
	p := socks5.NewReply(rep, socks5.ATYPIPv4, []byte{0x00, 0x00, 0x00, 0x00}, []byte{0x00, 0x00})
	_, err := p.WriteTo(conn)
	return err
}

func s5SendUDPReply(conn net.Conn, addr *net.UDPAddr) error {
	var atyp byte
	var bndAddr, bndPort []byte
	if ip4 := addr.IP.To4(); ip4 != nil {
		atyp = socks5.ATYPIPv4
		bndAddr = ip4
	} else {
		atyp = socks5.ATYPIPv6
		bndAddr = addr.IP
	}
	bndPort = make([]byte, 2)
	binary.BigEndian.PutUint16(bndPort, uint16(addr.Port))
	p := socks5.NewReply(socks5.RepSuccess, atyp, bndAddr, bndPort)
	_, err := p.WriteTo(conn)
	return err
}
