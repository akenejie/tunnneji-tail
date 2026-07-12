// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package netstack wires up gVisor's netstack into Tailscale.
package netstack

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tailscale/wireguard-go/conn"
	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
	"tailscale.com/envknob"
	"tailscale.com/feature/buildfeatures"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/net/ipset"
	"tailscale.com/net/netaddr"
	"tailscale.com/net/packet"
	"tailscale.com/net/tsaddr"
	"tailscale.com/net/tsdial"
	"tailscale.com/net/tstun"
	"tailscale.com/proxymap"
	"tailscale.com/syncs"
	"tailscale.com/tailcfg"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/logger"
	"tailscale.com/types/netmap"
	"tailscale.com/types/views"
	"tailscale.com/version"
	"tailscale.com/wgengine"
	"tailscale.com/wgengine/filter"
	"tailscale.com/wgengine/magicsock"
	"tailscale.com/wgengine/netstack/gro"
)

const debugPackets = false

// If non-zero, these override the values returned from the corresponding
// functions, below. They are accessed atomically because background
// goroutines in the gVisor TCP stack read them while test cleanup
// goroutines may be restoring them concurrently.
var (
	maxInFlightConnectionAttemptsForTest atomic.Int32
)

// maxInFlightConnectionAttempts returns the global number of in-flight
// connection attempts that we allow for a single netstack Impl. Any new
// forwarded TCP connections that are opened after the limit has been hit are
// rejected until the number of in-flight connections drops below the limit
// again.
//
// Each in-flight connection attempt is a new goroutine and an open TCP
// connection, so we want to ensure that we don't allow an unbounded number of
// connections.
func maxInFlightConnectionAttempts() int {
	if n := maxInFlightConnectionAttemptsForTest.Load(); n > 0 {
		return int(n)
	}

	if version.IsMobile() {
		return 1024 // previous global value
	}
	switch version.OS() {
	case "linux":
		// On the assumption that most subnet routers deployed in
		// production are running on Linux, we return a higher value.
		//
		// TODO(andrew-d): tune this based on the amount of system
		// memory instead of a fixed limit.
		return 8192
	default:
		// On all other platforms, return a reasonably high value that
		// most users won't hit.
		return 2048
	}
}

var debugNetstack = envknob.RegisterBool("TS_DEBUG_NETSTACK")

// netstackKeepaliveIdle overrides the netstack default (~2h) TCP keepalive
// idle time for forwarded connections. When a tailnet peer goes away without
// closing its connections (pod deleted, peer removed from netmap, silent
// network partition), the forwardTCP io.Copy goroutines block until keepalive
// fires. Under high-churn forwarding — many short-lived peers, or peers
// holding thousands of proxied connections that drop at once — the 2h default
// lets stuck goroutines accumulate faster than they clear. Value is a Go
// duration, e.g. "60s". See tailscale/tailscale#4522.
var netstackKeepaliveIdle = envknob.RegisterDuration("TS_NETSTACK_KEEPALIVE_IDLE")

// netstackKeepaliveInterval overrides the netstack default (75s) TCP keepalive
// probe interval for forwarded connections. Independent of
// netstackKeepaliveIdle; setting one without the other leaves the unset knob
// at the netstack default. Value is a Go duration, e.g. "15s".
var netstackKeepaliveInterval = envknob.RegisterDuration("TS_NETSTACK_KEEPALIVE_INTERVAL")

var (
	serviceIP   = tsaddr.TailscaleServiceIP()
	serviceIPv6 = tsaddr.TailscaleServiceIPv6()
)

func init() {
	mode := envknob.String("TS_DEBUG_NETSTACK_LEAK_MODE")
	if mode == "" {
		return
	}
	var lm refs.LeakMode
	if err := lm.Set(mode); err != nil {
		panic(err)
	}
	refs.SetLeakMode(lm)
}

// Impl contains the state for the netstack implementation,
// and implements wgengine.FakeImpl to act as a userspace network
// stack when Tailscale is running in fake mode.
type Impl struct {
	// ProcessLocalIPs is whether netstack should handle incoming
	// traffic directed at the Node.Addresses (local IPs).
	// It can only be set before calling Start.
	ProcessLocalIPs bool

	// ProcessSubnets is whether netstack should handle incoming
	// traffic destined to non-local IPs (i.e. whether it should
	// be a subnet router).
	// It can only be set before calling Start.
	ProcessSubnets bool

	ipstack   *stack.Stack
	linkEP    *linkEndpoint
	tundev    *tstun.Wrapper
	pm        *proxymap.Mapper
	logf      logger.Logf
	ctx       context.Context        // alive until Close
	ctxCancel context.CancelFunc     // called on Close
	injectWG  sync.WaitGroup         // wait for the inject goroutine
	lb        *ipnlocal.LocalBackend // or nil
	// AllowedIPsForPort, if non-nil, restricts which source IPs can connect
	// to each port. Key is port number, value is allowed source IP prefixes.
	AllowedIPsForPort map[uint16][]netip.Prefix
	// PasswordForPort, if non-nil, enables ChaCha20 encryption for data on the port.
	// Key is port number, value is the password used to derive the encryption key.
	PasswordForPort map[uint16]string
	// DropICMP, if true, causes netstack to silently drop all ICMP echo requests.
	// Used when the VPN is fully password-protected (untrusted).
	DropICMP bool
	// Before Start is called, there can IPv6 Neighbor Discovery from the
	// OS landing on netstack. We need to drop those packets until Start.
	ready atomic.Bool // set to true once Start has been called

	// atomicIsLocalIPFunc holds a func that reports whether an IP
	// is a local (non-subnet) Tailscale IP address of this
	// machine. It's always a non-nil func. It's changed on netmap
	// updates.
	atomicIsLocalIPFunc syncs.AtomicValue[func(netip.Addr) bool]

	mu sync.Mutex
	// connsOpenBySubnetIP keeps track of number of connections open
	// for each subnet IP temporarily registered on netstack for active
	// TCP connections, so they can be unregistered when connections are
	// closed.
	connsOpenBySubnetIP map[netip.Addr]int
}

const nicID = 1

// maxUDPPacketSize is the maximum size of a UDP packet we copy in
// startPacketCopy when relaying UDP packets. The user can configure
// the tailscale MTU to anything up to this size so we can potentially
// have a UDP packet as big as the MTU.
const maxUDPPacketSize = tstun.MaxPacketSize

func setTCPBufSizes(ipstack *stack.Stack) error {
	// tcpip.TCP{Receive,Send}BufferSizeRangeOption is gVisor's version of
	// Linux's tcp_{r,w}mem. Application within gVisor differs as some Linux
	// features are not (yet) implemented, and socket buffer memory is not
	// controlled within gVisor, e.g. we allocate *stack.PacketBuffer's for the
	// write path within Tailscale. Therefore, we loosen our understanding of
	// the relationship between these Linux and gVisor tunables. The chosen
	// values are biased towards higher throughput on high bandwidth-delay
	// product paths, except on memory-constrained platforms.
	tcpRXBufOpt := tcpip.TCPReceiveBufferSizeRangeOption{
		// Min is unused by gVisor at the time of writing, but partially plumbed
		// for application by the TCP_WINDOW_CLAMP socket option.
		Min: tcpRXBufMinSize,
		// Default is used by gVisor at socket creation.
		Default: tcpRXBufDefSize,
		// Max is used by gVisor to cap the advertised receive window post-read.
		// (tcp_moderate_rcvbuf=true, the default).
		Max: tcpRXBufMaxSize,
	}
	tcpipErr := ipstack.SetTransportProtocolOption(tcp.ProtocolNumber, &tcpRXBufOpt)
	if tcpipErr != nil {
		return fmt.Errorf("could not set TCP RX buf size: %v", tcpipErr)
	}
	tcpTXBufOpt := tcpip.TCPSendBufferSizeRangeOption{
		// Min in unused by gVisor at the time of writing.
		Min: tcpTXBufMinSize,
		// Default is used by gVisor at socket creation.
		Default: tcpTXBufDefSize,
		// Max is used by gVisor to cap the send window.
		Max: tcpTXBufMaxSize,
	}
	tcpipErr = ipstack.SetTransportProtocolOption(tcp.ProtocolNumber, &tcpTXBufOpt)
	if tcpipErr != nil {
		return fmt.Errorf("could not set TCP TX buf size: %v", tcpipErr)
	}
	return nil
}

// Create creates and populates a new Impl.
func Create(logf logger.Logf, tundev *tstun.Wrapper, e wgengine.Engine, mc *magicsock.Conn, dialer *tsdial.Dialer, pm *proxymap.Mapper) (*Impl, error) {
	if mc == nil {
		return nil, errors.New("nil magicsock.Conn")
	}
	if tundev == nil {
		return nil, errors.New("nil tundev")
	}
	if logf == nil {
		return nil, errors.New("nil logger")
	}
	if e == nil {
		return nil, errors.New("nil Engine")
	}
	if pm == nil {
		return nil, errors.New("nil proxymap.Mapper")
	}
	if dialer == nil {
		return nil, errors.New("nil Dialer")
	}
	ipstack := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4, icmp.NewProtocol6},
	})
	sackEnabledOpt := tcpip.TCPSACKEnabled(true) // TCP SACK is disabled by default
	tcpipErr := ipstack.SetTransportProtocolOption(tcp.ProtocolNumber, &sackEnabledOpt)
	if tcpipErr != nil {
		return nil, fmt.Errorf("could not enable TCP SACK: %v", tcpipErr)
	}
	// See https://github.com/tailscale/tailscale/issues/9707
	// gVisor's RACK performs poorly. ACKs do not appear to be handled in a
	// timely manner, leading to spurious retransmissions and a reduced
	// congestion window.
	tcpRecoveryOpt := tcpip.TCPRecovery(0)
	tcpipErr = ipstack.SetTransportProtocolOption(tcp.ProtocolNumber, &tcpRecoveryOpt)
	if tcpipErr != nil {
		return nil, fmt.Errorf("could not disable TCP RACK: %v", tcpipErr)
	}
	// gVisor defaults to reno at the time of writing. We explicitly set reno
	// congestion control in order to prevent unexpected changes. Netstack
	// has an int overflow in sender congestion window arithmetic that is more
	// prone to trigger with cubic congestion control.
	// See https://github.com/google/gvisor/issues/11632
	renoOpt := tcpip.CongestionControlOption("reno")
	tcpipErr = ipstack.SetTransportProtocolOption(tcp.ProtocolNumber, &renoOpt)
	if tcpipErr != nil {
		return nil, fmt.Errorf("could not set reno congestion control: %v", tcpipErr)
	}
	err := setTCPBufSizes(ipstack)
	if err != nil {
		return nil, err
	}
	supportedGSOKind := stack.GSONotSupported
	supportedGROKind := groNotSupported
	if runtime.GOOS == "linux" && buildfeatures.HasGRO {
		// TODO(jwhited): add Windows support https://github.com/tailscale/corp/issues/21874
		supportedGROKind = tcpGROSupported
		supportedGSOKind = stack.HostGSOSupported
	}
	linkEP := newLinkEndpoint(512, uint32(tstun.DefaultTUNMTU()), "", supportedGROKind)
	linkEP.SupportedGSOKind = supportedGSOKind
	if tcpipProblem := ipstack.CreateNIC(nicID, linkEP); tcpipProblem != nil {
		return nil, fmt.Errorf("could not create netstack NIC: %v", tcpipProblem)
	}
	// By default the netstack NIC will only accept packets for the IPs
	// registered to it. Since in some cases we dynamically register IPs
	// based on the packets that arrive, the NIC needs to accept all
	// incoming packets. The NIC won't receive anything it isn't meant to
	// since WireGuard will only send us packets that are meant for us.
	ipstack.SetPromiscuousMode(nicID, true)
	// Add IPv4 and IPv6 default routes, so all incoming packets from the Tailscale side
	// are handled by the one fake NIC we use.
	ipv4Subnet, err := tcpip.NewSubnet(tcpip.AddrFromSlice(make([]byte, 4)), tcpip.MaskFromBytes(make([]byte, 4)))
	if err != nil {
		return nil, fmt.Errorf("could not create IPv4 subnet: %v", err)
	}
	ipv6Subnet, err := tcpip.NewSubnet(tcpip.AddrFromSlice(make([]byte, 16)), tcpip.MaskFromBytes(make([]byte, 16)))
	if err != nil {
		return nil, fmt.Errorf("could not create IPv6 subnet: %v", err)
	}
	ipstack.SetRouteTable([]tcpip.Route{
		{
			Destination: ipv4Subnet,
			NIC:         nicID,
		},
		{
			Destination: ipv6Subnet,
			NIC:         nicID,
		},
	})
	ns := &Impl{
		logf:                  logf,
		ipstack:               ipstack,
		linkEP:                linkEP,
		tundev:                tundev,
		pm:                    pm,
		connsOpenBySubnetIP:   make(map[netip.Addr]int),
	}
	ns.ctx, ns.ctxCancel = context.WithCancel(context.Background())
	ns.atomicIsLocalIPFunc.Store(ipset.FalseContainsIPFunc())
	ns.tundev.PostFilterPacketInboundFromWireGuard = ns.injectInbound
	ns.tundev.PreFilterPacketOutboundToWireGuardNetstackIntercept = ns.handleLocalPackets
	return ns, nil
}

func (ns *Impl) Close() error {
	ns.ctxCancel()
	ns.ipstack.Close()
	ns.ipstack.Wait()
	ns.injectWG.Wait()
	return nil
}

type protocolHandlerFunc func(stack.TransportEndpointID, *stack.PacketBuffer) bool

// wrapUDPProtocolHandler wraps the protocol handler we pass to netstack for UDP.
func (ns *Impl) wrapUDPProtocolHandler(h protocolHandlerFunc) protocolHandlerFunc {
	return func(tei stack.TransportEndpointID, pb *stack.PacketBuffer) bool {
		addr := tei.LocalAddress
		ip, ok := netip.AddrFromSlice(addr.AsSlice())
		if !ok {
			ns.logf("netstack: could not parse local address for incoming connection")
			return false
		}

		// Dynamically reconfigure ns's subnet addresses as needed for
		// outbound traffic.
		ip = ip.Unmap()
		if !ns.isLocalIP(ip) {
			ns.addSubnetAddress(ip)
		}
		return h(tei, pb)
	}
}

// wrapTCPProtocolHandler wraps the protocol handler we pass to netstack for TCP.
func (ns *Impl) wrapTCPProtocolHandler(h protocolHandlerFunc) protocolHandlerFunc {
	return func(tei stack.TransportEndpointID, pb *stack.PacketBuffer) (handled bool) {
		localIP, ok := netip.AddrFromSlice(tei.LocalAddress.AsSlice())
		if !ok {
			ns.logf("netstack: could not parse local address for incoming connection")
			return false
		}
		localIP = localIP.Unmap()

		// Dynamically reconfigure ns's subnet addresses as needed for
		// outbound traffic.
		if !ns.isLocalIP(localIP) {
			ns.addSubnetAddress(localIP)
		}

		return h(tei, pb)
	}
}

// LocalBackend is a fake name for *ipnlocal.LocalBackend to avoid an import cycle.
type LocalBackend = any

// Start sets up all the handlers so netstack can start working. Implements
// wgengine.FakeImpl.
//
// The provided LocalBackend interface can be either nil, for special case users
// of netstack that don't have a LocalBackend, or a non-nil
// *ipnlocal.LocalBackend. Any other type will cause Start to panic.
//
// Start currently (2026-03-11) never returns a non-nil error, but maybe it did
// in the past and maybe it will in the future.
func (ns *Impl) Start(b LocalBackend) error {
	switch b := b.(type) {
	case nil:
		// No backend, so just continue with ns.lb unset.
	case *ipnlocal.LocalBackend:
		if b == nil {
			panic("nil LocalBackend")
		}
		ns.lb = b
	default:
		panic(fmt.Sprintf("unexpected type for LocalBackend: %T", b))
	}
	tcpFwd := tcp.NewForwarder(ns.ipstack, tcpRXBufDefSize, maxInFlightConnectionAttempts(), ns.acceptTCP)
	udpFwd := udp.NewForwarder(ns.ipstack, ns.acceptUDPNoICMP)
	ns.ipstack.SetTransportProtocolHandler(tcp.ProtocolNumber, ns.wrapTCPProtocolHandler(tcpFwd.HandlePacket))
	ns.ipstack.SetTransportProtocolHandler(udp.ProtocolNumber, ns.wrapUDPProtocolHandler(udpFwd.HandlePacket))
	ns.injectWG.Go(func() {
		ns.inject()
	})
	if ns.ready.Swap(true) {
		panic("already started")
	}
	return nil
}

func (ns *Impl) addSubnetAddress(ip netip.Addr) {
	ns.mu.Lock()
	ns.connsOpenBySubnetIP[ip]++
	needAdd := ns.connsOpenBySubnetIP[ip] == 1
	ns.mu.Unlock()
	// Only register address into netstack for first concurrent connection.
	if needAdd {
		pa := tcpip.ProtocolAddress{
			AddressWithPrefix: tcpip.AddrFromSlice(ip.AsSlice()).WithPrefix(),
		}
		if ip.Is4() {
			pa.Protocol = ipv4.ProtocolNumber
		} else if ip.Is6() {
			pa.Protocol = ipv6.ProtocolNumber
		}
		ns.ipstack.AddProtocolAddress(nicID, pa, stack.AddressProperties{
			PEB:        stack.CanBePrimaryEndpoint, // zero value default
			ConfigType: stack.AddressConfigStatic,  // zero value default
		})
	}
}

func (ns *Impl) removeSubnetAddress(ip netip.Addr) {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	ns.connsOpenBySubnetIP[ip]--
	// Only unregister address from netstack after last concurrent connection.
	if ns.connsOpenBySubnetIP[ip] == 0 {
		ns.ipstack.RemoveAddress(nicID, tcpip.AddrFromSlice(ip.AsSlice()))
		delete(ns.connsOpenBySubnetIP, ip)
	}
}

func ipPrefixToAddressWithPrefix(ipp netip.Prefix) tcpip.AddressWithPrefix {
	return tcpip.AddressWithPrefix{
		Address:   tcpip.AddrFromSlice(ipp.Addr().AsSlice()),
		PrefixLen: int(ipp.Bits()),
	}
}

var v4broadcast = netaddr.IPv4(255, 255, 255, 255)

// UpdateNetstackIPs updates the set of local IPs that netstack should handle
// from nm.
//
// TODO(bradfitz): don't pass the whole netmap here; just pass the two
// address slice views.
func (ns *Impl) UpdateNetstackIPs(nm *netmap.NetworkMap) {
	var selfNode tailcfg.NodeView
	if nm != nil {
		ns.atomicIsLocalIPFunc.Store(ipset.NewContainsIPFunc(nm.GetAddresses()))
		selfNode = nm.SelfNode
	} else {
		ns.atomicIsLocalIPFunc.Store(ipset.FalseContainsIPFunc())
	}

	oldPfx := make(map[netip.Prefix]bool)
	for _, protocolAddr := range ns.ipstack.AllAddresses()[nicID] {
		ap := protocolAddr.AddressWithPrefix
		ip := netaddrIPFromNetstackIP(ap.Address)
		if ip == v4broadcast && ap.PrefixLen == 32 {
			// Don't add 255.255.255.255/32 to oldIPs so we don't
			// delete it later. We didn't install it, so it's not
			// ours to delete.
			continue
		}
		p := netip.PrefixFrom(ip, ap.PrefixLen)
		oldPfx[p] = true
	}
	newPfx := make(map[netip.Prefix]bool)

	if selfNode.Valid() {
		for _, p := range selfNode.Addresses().All() {
			newPfx[p] = true
		}
		if ns.ProcessSubnets {
			for _, p := range selfNode.AllowedIPs().All() {
				newPfx[p] = true
			}
		}
	}

	pfxToAdd := make(map[netip.Prefix]bool)
	for p := range newPfx {
		if !oldPfx[p] {
			pfxToAdd[p] = true
		}
	}
	pfxToRemove := make(map[netip.Prefix]bool)
	for p := range oldPfx {
		if !newPfx[p] {
			pfxToRemove[p] = true
		}
	}
	ns.mu.Lock()
	for ip := range ns.connsOpenBySubnetIP {
		// TODO(maisem): this looks like a bug, remove or document. It seems as
		// though we might end up either leaking the address on the netstack
		// NIC, or where we do accounting for connsOpenBySubnetIP from 1 to 0,
		// we might end up removing the address from the netstack NIC that was
		// still being advertised.
		delete(pfxToRemove, netip.PrefixFrom(ip, ip.BitLen()))
	}
	ns.mu.Unlock()

	for p := range pfxToRemove {
		err := ns.ipstack.RemoveAddress(nicID, tcpip.AddrFromSlice(p.Addr().AsSlice()))
		if err != nil {
			ns.logf("netstack: could not deregister IP %s: %v", p, err)
		} else {
			ns.logf("[v2] netstack: deregistered IP %s", p)
		}
	}
	for p := range pfxToAdd {
		if !p.IsValid() {
			ns.logf("netstack: [unexpected] skipping invalid IP (%v/%v)", p.Addr(), p.Bits())
			continue
		}
		tcpAddr := tcpip.ProtocolAddress{
			AddressWithPrefix: ipPrefixToAddressWithPrefix(p),
		}
		if p.Addr().Is6() {
			tcpAddr.Protocol = ipv6.ProtocolNumber
		} else {
			tcpAddr.Protocol = ipv4.ProtocolNumber
		}
		var tcpErr tcpip.Error // not error
		tcpErr = ns.ipstack.AddProtocolAddress(nicID, tcpAddr, stack.AddressProperties{
			PEB:        stack.CanBePrimaryEndpoint, // zero value default
			ConfigType: stack.AddressConfigStatic,  // zero value default
		})
		if tcpErr != nil {
			ns.logf("netstack: could not register IP %s: %v", p, tcpErr)
		} else {
			ns.logf("[v2] netstack: registered IP %s", p)
		}
	}
}

func (ns *Impl) UpdateIPServiceMappings(m netmap.IPServiceMappings) {}
func (ns *Impl) UpdateActiveVIPServices(v views.Slice[string])     {}

// handleLocalPackets is hooked into the tun datapath for packets leaving
// the host and arriving at tailscaled. This method returns filter.DropSilently
// to intercept a packet for handling, for instance traffic to quad-100.
// Caution: can be called before Start
func (ns *Impl) handleLocalPackets(p *packet.Parsed, t *tstun.Wrapper, gro *gro.GRO) (filter.Response, *gro.GRO) {
	if !ns.ready.Load() || ns.ctx.Err() != nil {
		return filter.DropSilently, gro
	}

	// Determine if we care about this local packet.
	dst := p.Dst.Addr()
	switch {
	case dst == serviceIP || dst == serviceIPv6:
		// Traffic to the Tailscale service IP (100.100.100.100 /
		// fd7a:115c:a1e0::53) is always terminated locally on this
		// node; it must never be forwarded out over WireGuard to a
		// peer. Absorb all quad-100 traffic into netstack so it never
		// reaches the conntrack / peer-routing layers.
	default:
		// Not traffic to the service IP, so we don't care about the
		// packet; resume processing.
		return filter.Accept, gro
	}
	if debugPackets {
		ns.logf("[v2] service packet in (from %v): % x", p.Src, p.Buffer())
	}

	gro = ns.linkEP.gro(p, gro)
	return filter.DropSilently, gro
}

func (ns *Impl) DialContextTCP(ctx context.Context, ipp netip.AddrPort) (*gonet.TCPConn, error) {
	remoteAddress := tcpip.FullAddress{
		NIC:  nicID,
		Addr: tcpip.AddrFromSlice(ipp.Addr().AsSlice()),
		Port: ipp.Port(),
	}
	var ipType tcpip.NetworkProtocolNumber
	if ipp.Addr().Is4() {
		ipType = ipv4.ProtocolNumber
	} else {
		ipType = ipv6.ProtocolNumber
	}

	return gonet.DialContextTCP(ctx, ns.ipstack, remoteAddress, ipType)
}

func (ns *Impl) DialContextUDP(ctx context.Context, ipp netip.AddrPort) (*gonet.UDPConn, error) {
	remoteAddress := &tcpip.FullAddress{
		NIC:  nicID,
		Addr: tcpip.AddrFromSlice(ipp.Addr().AsSlice()),
		Port: ipp.Port(),
	}
	var ipType tcpip.NetworkProtocolNumber
	if ipp.Addr().Is4() {
		ipType = ipv4.ProtocolNumber
	} else {
		ipType = ipv6.ProtocolNumber
	}

	return gonet.DialUDP(ns.ipstack, nil, remoteAddress, ipType)
}

// getInjectInboundBuffsSizes returns packet memory and a sizes slice for usage
// when calling tstun.Wrapper.InjectInboundPacketBuffer(). These are sized with
// consideration for MTU and GSO support on ns.linkEP. They should be recycled
// across subsequent inbound packet injection calls.
func (ns *Impl) getInjectInboundBuffsSizes() (buffs [][]byte, sizes []int) {
	batchSize := 1
	gsoEnabled := ns.linkEP.SupportedGSO() == stack.HostGSOSupported
	if gsoEnabled {
		batchSize = conn.IdealBatchSize
	}
	buffs = make([][]byte, batchSize)
	sizes = make([]int, batchSize)
	for i := 0; i < batchSize; i++ {
		if i == 0 && gsoEnabled {
			buffs[i] = make([]byte, tstun.PacketStartOffset+ns.linkEP.GSOMaxSize())
		} else {
			buffs[i] = make([]byte, tstun.PacketStartOffset+tstun.DefaultTUNMTU())
		}
	}
	return buffs, sizes
}

// The inject goroutine reads in packets that netstack generated, and delivers
// them to the correct path.
func (ns *Impl) inject() {
	inboundBuffs, inboundBuffsSizes := ns.getInjectInboundBuffsSizes()
	for {
		pkt := ns.linkEP.ReadContext(ns.ctx)
		if pkt == nil {
			if ns.ctx.Err() != nil {
				// Return without logging.
				return
			}
			ns.logf("[v2] ReadContext-for-write = ok=false")
			continue
		}

		if debugPackets {
			ns.logf("[v2] packet Write out: % x", stack.PayloadSince(pkt.NetworkHeader()).AsSlice())
		}

		// In the normal case, netstack synthesizes the bytes for
		// traffic which should transit back into WG and go to peers.
		// However, some uses of netstack (presently, magic DNS)
		// send traffic destined for the local device, hence must
		// be injected 'inbound'.
		sendToHost := ns.shouldSendToHost(pkt)

		// pkt has a non-zero refcount, so injection methods takes
		// ownership of one count and will decrement on completion.
		if sendToHost {
			if err := ns.tundev.InjectInboundPacketBuffer(pkt, inboundBuffs, inboundBuffsSizes); err != nil {
				ns.logf("netstack inject inbound: %v", err)
				return
			}
		} else {
			// Self-addressed packet: deliver back into gVisor directly
			// via the link endpoint's dispatcher, but only if the packet is not
			// earmarked for the host. Neither the inbound path (fakeTUN Write is a
			// no-op) nor the outbound path (WireGuard has no peer for our own IP)
			// can handle these.
			if ns.isSelfDst(pkt) {
				ns.linkEP.DeliverLoopback(pkt)
				continue
			}

			if err := ns.tundev.InjectOutboundPacketBuffer(pkt); err != nil {
				ns.logf("netstack inject outbound: %v", err)
				return
			}
		}
	}
}

// shouldSendToHost determines if the provided packet should be sent to the
// host (i.e the current machine running Tailscale), in which case it will
// return true. It will return false if the packet should be sent outbound, for
// transit via WireGuard to another Tailscale node.
func (ns *Impl) shouldSendToHost(pkt *stack.PacketBuffer) bool {
	hdr := pkt.Network()
	switch v := hdr.(type) {
	case header.IPv4:
		srcIP := netip.AddrFrom4(v.SourceAddress().As4())
		if serviceIP == srcIP {
			return true
		}
	case header.IPv6:
		srcIP := netip.AddrFrom16(v.SourceAddress().As16())
		if srcIP == serviceIPv6 {
			return true
		}
	default:
		if debugNetstack() {
			ns.logf("netstack: unexpected packet in shouldSendToHost: %T", v)
		}
	}

	return false
}

// isSelfDst reports whether pkt's destination IP is a local Tailscale IP
// assigned to this node. This is used by inject() to detect self-addressed
// packets that need loopback delivery.
func (ns *Impl) isSelfDst(pkt *stack.PacketBuffer) bool {
	hdr := pkt.Network()
	switch v := hdr.(type) {
	case header.IPv4:
		return ns.isLocalIP(netip.AddrFrom4(v.DestinationAddress().As4()))
	case header.IPv6:
		return ns.isLocalIP(netip.AddrFrom16(v.DestinationAddress().As16()))
	}
	return false
}

// isLocalIP reports whether ip is a Tailscale IP assigned to this
// node directly (but not a subnet-routed IP).
func (ns *Impl) isLocalIP(ip netip.Addr) bool {
	return ns.atomicIsLocalIPFunc.Load()(ip)
}

var viaRange = tsaddr.TailscaleViaRange()

// shouldProcessInbound reports whether an inbound packet (a packet from a
// WireGuard peer) should be handled by netstack.
func (ns *Impl) shouldProcessInbound(p *packet.Parsed, t *tstun.Wrapper) bool {
	dstIP := p.Dst.Addr()
	isLocal := ns.isLocalIP(dstIP)

	// Handle TCP connections to the Tailscale IP(s):
	if ns.lb != nil && p.IPProto == ipproto.TCP && isLocal {
		dport := p.Dst.Port()
		// Handle SSH connections, webserver, etc, if enabled:
		if ns.lb.ShouldInterceptTCPPort(dport) {
			return true
		}
	}
	if ns.ProcessLocalIPs && isLocal {
		return true
	}
	if ns.ProcessSubnets && !isLocal {
		return true
	}
	return false
}

var userPingSem = syncs.NewSemaphore(20) // 20 child ping processes at once

// userPing tried to ping dstIP and if it succeeds, injects pingResPkt
// into the tundev as an outbound packet.
//
// It's used in userspace/netstack mode when we don't have kernel
// support or raw socket access. As such, this does the dumbest thing
// that can work: runs the ping command. It's not super efficient, so
// it bounds the number of pings going on at once. The idea is that
// people only use ping occasionally to see if their internet's working
// so this doesn't need to be great.
// On Apple platforms, this function doesn't run the ping command. Instead,
// it sends a non-privileged ping.
//
// TODO(bradfitz): when we're running on Windows as the system user, use
// raw socket APIs instead of ping child processes.
func (ns *Impl) userPing(dstIP netip.Addr, pingResPkt []byte) {
	if !userPingSem.TryAcquire() {
		return
	}
	defer userPingSem.Release()

	t0 := time.Now()
	err := ns.sendOutboundUserPing(dstIP, 3*time.Second)
	d := time.Since(t0)
	if err != nil {
		if d < time.Second/2 {
			// If it failed quicker than the 3 second
			// timeout we gave above (500 ms is a
			// reasonable threshold), then assume the ping
			// failed for problems finding/running
			// ping. We don't want to log if the host is
			// just down.
			ns.logf("exec ping of %v failed in %v: %v", dstIP, d, err)
		}
		return
	}
	if debugNetstack() {
		ns.logf("exec pinged %v in %v", dstIP, time.Since(t0))
	}
	if err := ns.tundev.InjectOutbound(pingResPkt); err != nil {
		ns.logf("InjectOutbound ping response: %v", err)
	}
}

// injectInbound is installed as a packet hook on the 'inbound' (from a
// WireGuard peer) path. Returning filter.Accept releases the packet to
// continue normally (typically being delivered to the host networking stack),
// whereas returning filter.DropSilently is done when netstack intercepts the
// packet and no further processing towards to host should be done.
// Caution: can be called before Start
func (ns *Impl) injectInbound(p *packet.Parsed, t *tstun.Wrapper, gro *gro.GRO) (filter.Response, *gro.GRO) {
	if !ns.ready.Load() || ns.ctx.Err() != nil {
		return filter.DropSilently, gro
	}

	if !ns.shouldProcessInbound(p, t) {
		// Let the host network stack (if any) deal with it.
		return filter.Accept, gro
	}

	destIP := p.Dst.Addr()

	// If this is an echo request and we're a subnet router, handle pings
	// ourselves instead of forwarding the packet on.
	if ns.DropICMP && p.IsEchoRequest() {
		return filter.DropSilently, gro
	}
	pingIP, handlePing := ns.shouldHandlePing(p)
	if handlePing {
		var pong []byte // the reply to the ping, if our relayed ping works
		if destIP.Is4() {
			h := p.ICMP4Header()
			h.ToResponse()
			pong = packet.Generate(&h, p.Payload())
		} else if destIP.Is6() {
			h := p.ICMP6Header()
			h.ToResponse()
			pong = packet.Generate(&h, p.Payload())
		}
		go ns.userPing(pingIP, pong)
		return filter.DropSilently, gro
	}

	if debugPackets {
		ns.logf("[v2] packet in (from %v): % x", p.Src, p.Buffer())
	}
	gro = ns.linkEP.gro(p, gro)

	// We've now delivered this to netstack, so we're done.
	// Instead of returning a filter.Accept here (which would also
	// potentially deliver it to the host OS), and instead of
	// filter.Drop (which would log about rejected traffic),
	// instead return filter.DropSilently which just quietly stops
	// processing it in the tstun TUN wrapper.
	return filter.DropSilently, gro
}

// shouldHandlePing returns whether or not netstack should handle an incoming
// ICMP echo request packet, and the IP address that should be pinged from this
// process. The IP address can be different from the destination in the packet
// if the destination is a 4via6 address.
func (ns *Impl) shouldHandlePing(p *packet.Parsed) (_ netip.Addr, ok bool) {
	if !p.IsEchoRequest() {
		return netip.Addr{}, false
	}

	destIP := p.Dst.Addr()

	// We need to handle pings for all 4via6 addresses, even if this
	// netstack instance normally isn't responsible for processing subnets.
	//
	// For example, on Linux, subnet router traffic could be handled via
	// tun+iptables rules for most packets, but we still need to handle
	// ICMP echo requests over 4via6 since the host networking stack
	// doesn't know what to do with a 4via6 address.
	//
	// shouldProcessInbound returns 'true' to say that we should process
	// all IPv6 packets with a destination address in the 'via' range, so
	// check before we check the "ProcessSubnets" boolean below.
	if viaRange.Contains(destIP) {
		// The input echo request was to a 4via6 address, which we cannot
		// simply ping as-is from this process. Translate the destination to an
		// IPv4 address, so that our relayed ping (in userPing) is pinging the
		// underlying destination IP.
		//
		// ICMPv4 and ICMPv6 are different protocols with different on-the-wire
		// representations, so normally you can't send an ICMPv6 message over
		// IPv4 and expect to get a useful result. However, in this specific
		// case things are safe because the 'userPing' function doesn't make
		// use of the input packet.
		return tsaddr.UnmapVia(destIP), true
	}

	// If we get here, we don't do anything unless this netstack instance
	// is responsible for processing subnet traffic.
	if !ns.ProcessSubnets {
		return netip.Addr{}, false
	}

	// For non-4via6 addresses, we don't handle pings if they're destined
	// for a Tailscale IP.
	if tsaddr.IsTailscaleIP(destIP) {
		return netip.Addr{}, false
	}

	// This netstack instance is processing subnet traffic, so handle the
	// ping ourselves.
	return destIP, true
}

func netaddrIPFromNetstackIP(s tcpip.Address) netip.Addr {
	switch s.Len() {
	case 4:
		return netip.AddrFrom4(s.As4())
	case 16:
		return netip.AddrFrom16(s.As16()).Unmap()
	}
	return netip.Addr{}
}

var (
	ipv4Loopback = netip.MustParseAddr("127.0.0.1")
	ipv6Loopback = netip.MustParseAddr("::1")
)

func (ns *Impl) acceptTCP(r *tcp.ForwarderRequest) {
	reqDetails := r.ID()
	if debugNetstack() {
		ns.logf("[v2] TCP ForwarderRequest: %s", stringifyTEI(reqDetails))
	}
	clientRemoteIP := netaddrIPFromNetstackIP(reqDetails.RemoteAddress)
	if !clientRemoteIP.IsValid() {
		ns.logf("invalid RemoteAddress in TCP ForwarderRequest: %s", stringifyTEI(reqDetails))
		r.Complete(true) // sends a RST
		return
	}

	clientRemotePort := reqDetails.RemotePort
	clientRemoteAddrPort := netip.AddrPortFrom(clientRemoteIP, clientRemotePort)

	dialIP := netaddrIPFromNetstackIP(reqDetails.LocalAddress)
	isTailscaleIP := tsaddr.IsTailscaleIP(dialIP)
	isLocal := ns.isLocalIP(dialIP) // i.e. not a subnet routed or 4via6 target

	dstAddrPort := netip.AddrPortFrom(dialIP, reqDetails.LocalPort)

	if viaRange.Contains(dialIP) {
		isTailscaleIP = false
		dialIP = tsaddr.UnmapVia(dialIP)
	}

	defer func() {
		if !isTailscaleIP {
			// if this is a subnet IP, we added this in before the TCP handshake
			// so netstack is happy TCP-handshaking as a subnet IP
			ns.removeSubnetAddress(dialIP)
		}
	}()

	var wq waiter.Queue

	// We can't actually create the endpoint or complete the inbound
	// request until we're sure that the connection can be handled by this
	// endpoint. This function sets up the TCP connection and should be
	// called immediately before a connection is handled.
	getConnOrReset := func(opts ...tcpip.SettableSocketOption) *gonet.TCPConn {
		ep, err := r.CreateEndpoint(&wq)
		if err != nil {
			ns.logf("CreateEndpoint error for %s: %v", stringifyTEI(reqDetails), err)
			r.Complete(true) // sends a RST
			return nil
		}
		r.Complete(false)
		for _, opt := range opts {
			ep.SetSockOpt(opt)
		}
		// SetKeepAlive so that idle connections to peers that have forgotten about
		// the connection or gone completely offline eventually time out.
		// Applications might be setting this on a forwarded connection, but from
		// userspace we can not see those, so the best we can do is to always
		// perform them with conservative timing.
		// Netstack defaults match the Linux defaults and result in a little over
		// two hours before the socket is closed due to keepalive. Operators can
		// shorten the timers with TS_NETSTACK_KEEPALIVE_IDLE and
		// TS_NETSTACK_KEEPALIVE_INTERVAL (see netstackKeepaliveIdle); the
		// defaults are left unchanged because the long timers are low-impact for
		// battery-powered peers and this has broad implications in userspace
		// mode (lingering connections to fork-style daemons, etc). See
		// tailscale/tailscale#4522.
		if d := netstackKeepaliveIdle(); d > 0 {
			idle := tcpip.KeepaliveIdleOption(d)
			if err := ep.SetSockOpt(&idle); err != nil {
				ns.logf("netstack: SetSockOpt(KeepaliveIdle=%v) failed: %v", d, err)
			}
		}
		if d := netstackKeepaliveInterval(); d > 0 {
			intvl := tcpip.KeepaliveIntervalOption(d)
			if err := ep.SetSockOpt(&intvl); err != nil {
				ns.logf("netstack: SetSockOpt(KeepaliveInterval=%v) failed: %v", d, err)
			}
		}
		ep.SocketOptions().SetKeepAlive(true)

		// The ForwarderRequest.CreateEndpoint above asynchronously
		// starts the TCP handshake. Note that the gonet.TCPConn
		// methods c.RemoteAddr() and c.LocalAddr() will return nil
		// until the handshake actually completes. But we have the
		// remote address in reqDetails instead, so we don't use
		// gonet.TCPConn.RemoteAddr. The byte copies in both
		// directions to/from the gonet.TCPConn in forwardTCP will
		// block until the TCP handshake is complete.
		return gonet.NewTCPConn(&wq, ep)
	}

	// Local Services (DNS and WebDAV)
	hittingServiceIP := dialIP == serviceIP || dialIP == serviceIPv6
	hittingDNS := hittingServiceIP && reqDetails.LocalPort == 53
	if hittingDNS {
		return // DNS not supported, drop silently
	}

	if ns.lb != nil {
		// Check IP filter for this port
		if ns.AllowedIPsForPort != nil {
			if allowed, ok := ns.AllowedIPsForPort[reqDetails.LocalPort]; ok {
				srcIP := clientRemoteAddrPort.Addr()
				found := false
				for _, pfx := range allowed {
					if pfx.Contains(srcIP) {
						found = true
						break
					}
				}
				if !found {
					return // source IP not allowed, drop silently
				}
			}
		}
		handler, opts := ns.lb.TCPHandlerForDst(clientRemoteAddrPort, dstAddrPort)
		if handler != nil {
			c := getConnOrReset(opts...) // will send a RST if it fails
			if c == nil {
				return
			}
			// Wrap with encryption if password is set for this port
			if ns.PasswordForPort != nil {
				if password, ok := ns.PasswordForPort[reqDetails.LocalPort]; ok {
					encConn, err := newEncryptedTCPConn(c, password)
					if err != nil {
						ns.logf("Failed to create encrypted conn for port %d: %v", reqDetails.LocalPort, err)
						c.Close()
						return
					}
					handler(encConn)
					return
				}
			}
			handler(c)
			return
		}
	}

	switch {
	case hittingServiceIP:
		// TCP to the Tailscale service IP on a port we don't serve
		// (anything other than DNS/53, web client/80, Taildrive/8080,
		// or the debug loopback port handled above). handleLocalPackets
		// absorbs all quad-100 traffic into netstack to prevent it
		// from leaking to WireGuard peers as noisy "open-conn-track:
		// timeout opening ...; no associated peer node" log lines
		// (see the comment there).
		//
		// Without this explicit guard, execution would fall through
		// to the isTailscaleIP case below (quad-100 is in the
		// tailscale IP range), rewriting the dial target to
		// 127.0.0.1:<port> and forwardTCP'ing the connection onto
		// whatever random service happens to be listening on the
		// host's loopback at that port. Reject cleanly with a RST
		// here instead.
		r.Complete(true) // sends a RST
		return
	case isTailscaleIP:
		dialIP = ipv4Loopback
	}
	dialAddr := netip.AddrPortFrom(dialIP, uint16(reqDetails.LocalPort))

	if !ns.forwardTCP(getConnOrReset, clientRemoteIP, &wq, dialAddr, isLocal) {
		r.Complete(true) // sends a RST
	}
}

// tcpCloser is an interface to abstract around various TCPConn types that
// allow closing of the read and write streams independently of each other.
type tcpCloser interface {
	CloseRead() error
	CloseWrite() error
}

func (ns *Impl) forwardTCP(getClient func(...tcpip.SettableSocketOption) *gonet.TCPConn, clientRemoteIP netip.Addr, wq *waiter.Queue, dialAddr netip.AddrPort, isLocal bool) (handled bool) {
	dialAddrStr := dialAddr.String()
	if debugNetstack() {
		ns.logf("[v2] netstack: forwarding incoming connection to %s", dialAddrStr)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	waitEntry, notifyCh := waiter.NewChannelEntry(waiter.EventHUp) // TODO(bradfitz): right EventMask?
	wq.EventRegister(&waitEntry)
	defer wq.EventUnregister(&waitEntry)
	done := make(chan bool)
	// netstack doesn't close the notification channel automatically if there was no
	// hup signal, so we close done after we're done to not leak the goroutine below.
	defer close(done)
	go func() {
		select {
		case <-notifyCh:
			if debugNetstack() {
				ns.logf("[v2] netstack: forwardTCP notifyCh fired; canceling context for %s", dialAddrStr)
			}
		case <-done:
		}
		cancel()
	}()

	// Attempt to dial the outbound connection before we accept the inbound one.
	var stdDialer net.Dialer
	dialFunc := stdDialer.DialContext

	// TODO: this is racy, dialing before we register our local address. See
	// https://github.com/tailscale/tailscale/issues/1616.
	backend, err := dialFunc(ctx, "tcp", dialAddrStr)
	if err != nil {
		ns.logf("netstack: could not connect to local backend server at %s: %v", dialAddr.String(), err)
		return
	}
	defer backend.Close()

	backendLocalAddr := backend.LocalAddr().(*net.TCPAddr)
	backendLocalIPPort := netaddr.Unmap(backendLocalAddr.AddrPort())
	if isLocal {
		if err := ns.pm.RegisterIPPortIdentity("tcp", backendLocalIPPort, clientRemoteIP); err != nil {
			ns.logf("netstack: could not register TCP mapping %s: %v", backendLocalIPPort, err)
			return
		}
		defer ns.pm.UnregisterIPPortIdentity("tcp", backendLocalIPPort)
	}

	// If we get here, either the getClient call below will succeed and
	// return something we can Close, or it will fail and will properly
	// respond to the client with a RST. Either way, the caller no longer
	// needs to clean up the client connection.
	handled = true

	// We dialed the connection; we can complete the client's TCP handshake.
	client := getClient()
	if client == nil {
		return
	}
	defer client.Close()

	// As of 2025-07-03, backend is always either a net.TCPConn
	// from stdDialer.DialContext (which has the requisite functions),
	// or nil from hangDialer in tests (in which case we would have
	// errored out by now), so this conversion should always succeed.
	backendTCPCloser, backendIsTCPCloser := backend.(tcpCloser)
	connClosed := make(chan error, 2)
	go func() {
		_, err := io.Copy(backend, client)
		if err != nil {
			err = fmt.Errorf("client -> backend: %w", err)
		}
		connClosed <- err
		err = nil
		if backendIsTCPCloser {
			err = backendTCPCloser.CloseWrite()
		}
		err = errors.Join(err, client.CloseRead())
		if err != nil {
			ns.logf("client -> backend close connection: %v", err)
		}
	}()
	go func() {
		_, err := io.Copy(client, backend)
		if err != nil {
			err = fmt.Errorf("backend -> client: %w", err)
		}
		connClosed <- err
		err = nil
		if backendIsTCPCloser {
			err = backendTCPCloser.CloseRead()
		}
		err = errors.Join(err, client.CloseWrite())
		if err != nil {
			ns.logf("backend -> client close connection: %v", err)
		}
	}()
	// Wait for both ends of the connection to close.
	for range 2 {
		err = <-connClosed
		if err != nil {
			ns.logf("proxy connection closed with error: %v", err)
		}
	}
	ns.logf("[v2] netstack: forwarder connection to %s closed", dialAddrStr)
	return
}



// acceptUDPNoICMP wraps acceptUDP to satisfy udp.ForwarderHandler.
// A gvisor bump from 9414b50a to 573d5e71 on 2026-02-27 changed
// udp.ForwarderHandler from func(*ForwarderRequest) to
// func(*ForwarderRequest) bool, where returning false means unhandled
// and causes gvisor to send an ICMP port unreachable. Previously there
// was no such distinction and all packets were implicitly treated as
// handled. Always returning true preserves the old behavior of silently
// dropping packets we don't service rather than sending ICMP errors.
func (ns *Impl) acceptUDPNoICMP(r *udp.ForwarderRequest) bool {
	ns.acceptUDP(r)
	return true
}

func (ns *Impl) acceptUDP(r *udp.ForwarderRequest) {
	sess := r.ID()
	if debugNetstack() {
		ns.logf("[v2] UDP ForwarderRequest: %v", stringifyTEI(sess))
	}
	var wq waiter.Queue
	ep, err := r.CreateEndpoint(&wq)
	if err != nil {
		ns.logf("acceptUDP: could not create endpoint: %v", err)
		return
	}
	dstAddr, ok := ipPortOfNetstackAddr(sess.LocalAddress, sess.LocalPort)
	if !ok {
		ep.Close()
		return
	}
	srcAddr, ok := ipPortOfNetstackAddr(sess.RemoteAddress, sess.RemotePort)
	if !ok {
		ep.Close()
		return
	}

	// Handle traffic to service IPs.
	if dst := dstAddr.Addr(); dst == serviceIP || dst == serviceIPv6 {
		switch {
		case dstAddr.Port() == 53:
			ep.Close()
			return // DNS not supported, drop silently
		default:
			ep.Close()
			return // Only DNS runs on the service IPs for now.
		}
	}

	c := gonet.NewUDPConn(&wq, ep)
	go ns.forwardUDP(c, srcAddr, dstAddr)
}

// Buffer pool for forwarding UDP packets. Use the maximum possible UDP packet
// size to avoid fragmenting.
var udpBufPool = &sync.Pool{
	New: func() any {
		b := make([]byte, maxUDPPacketSize)
		return &b
	},
}

// forwardUDP proxies between client (with addr clientAddr) and dstAddr.
//
// dstAddr may be either a local Tailscale IP, in which we case we proxy to
// 127.0.0.1, or any other IP (from an advertised subnet), in which case we
// proxy to it directly.
func (ns *Impl) forwardUDP(client *gonet.UDPConn, clientAddr, dstAddr netip.AddrPort) {
	port, srcPort := dstAddr.Port(), clientAddr.Port()
	if debugNetstack() {
		ns.logf("[v2] netstack: forwarding incoming UDP connection on port %v", port)
	}

	var backendListenAddr *net.UDPAddr
	var backendRemoteAddr *net.UDPAddr
	isLocal := ns.isLocalIP(dstAddr.Addr())
	isLoopback := dstAddr.Addr() == ipv4Loopback || dstAddr.Addr() == ipv6Loopback
	if isLocal {
		backendRemoteAddr = &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: int(port)}
		backendListenAddr = &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: int(srcPort)}
	} else if isLoopback {
		ip := net.IP(ipv4Loopback.AsSlice())
		if dstAddr.Addr() == ipv6Loopback {
			ip = ipv6Loopback.AsSlice()
		}
		backendRemoteAddr = &net.UDPAddr{IP: ip, Port: int(port)}
		backendListenAddr = &net.UDPAddr{IP: ip, Port: int(srcPort)}
	} else {
		if dstIP := dstAddr.Addr(); viaRange.Contains(dstIP) {
			dstAddr = netip.AddrPortFrom(tsaddr.UnmapVia(dstIP), dstAddr.Port())
		}
		backendRemoteAddr = net.UDPAddrFromAddrPort(dstAddr)
		if dstAddr.Addr().Is4() {
			backendListenAddr = &net.UDPAddr{IP: net.ParseIP("0.0.0.0"), Port: int(srcPort)}
		} else {
			backendListenAddr = &net.UDPAddr{IP: net.ParseIP("::"), Port: int(srcPort)}
		}
	}

	backendConn, err := net.ListenUDP("udp", backendListenAddr)
	if err != nil {
		ns.logf("netstack: could not bind local port %v: %v, trying again with random port", backendListenAddr.Port, err)
		backendListenAddr.Port = 0
		backendConn, err = net.ListenUDP("udp", backendListenAddr)
		if err != nil {
			ns.logf("netstack: could not create UDP socket, preventing forwarding to %v: %v", dstAddr, err)
			return
		}
	}
	backendLocalAddr := backendConn.LocalAddr().(*net.UDPAddr)

	backendLocalIPPort := netip.AddrPortFrom(backendListenAddr.AddrPort().Addr().Unmap().WithZone(backendLocalAddr.Zone), backendLocalAddr.AddrPort().Port())
	if !backendLocalIPPort.IsValid() {
		ns.logf("could not get backend local IP:port from %v:%v", backendLocalAddr.IP, backendLocalAddr.Port)
	}
	if isLocal {
		if err := ns.pm.RegisterIPPortIdentity("udp", backendLocalIPPort, clientAddr.Addr()); err != nil {
			ns.logf("netstack: could not register UDP mapping %s: %v", backendLocalIPPort, err)
			return
		}
	}
	ctx, cancel := context.WithCancel(context.Background())

	idleTimeout := 2 * time.Minute
	if port == 53 {
		// Make DNS packet copies time out much sooner.
		//
		// TODO(bradfitz): make DNS queries over UDP forwarding even
		// cheaper by adding an additional idleTimeout post-DNS-reply.
		// For instance, after the DNS response goes back out, then only
		// wait a few seconds (or zero, really)
		idleTimeout = 30 * time.Second
	}
	timer := time.AfterFunc(idleTimeout, func() {
		if isLocal {
			ns.pm.UnregisterIPPortIdentity("udp", backendLocalIPPort)
		}
		ns.logf("netstack: UDP session between %s and %s timed out", backendListenAddr, backendRemoteAddr)
		cancel()
		client.Close()
		backendConn.Close()
	})
	extend := func() {
		timer.Reset(idleTimeout)
	}
	startPacketCopy(ctx, cancel, client, net.UDPAddrFromAddrPort(clientAddr), backendConn, ns.logf, extend)
	startPacketCopy(ctx, cancel, backendConn, backendRemoteAddr, client, ns.logf, extend)
	if isLocal {
		// Wait for the copies to be done before decrementing the
		// subnet address count to potentially remove the route.
		<-ctx.Done()
		ns.removeSubnetAddress(dstAddr.Addr())
	}
}

func startPacketCopy(ctx context.Context, cancel context.CancelFunc, dst net.PacketConn, dstAddr net.Addr, src net.PacketConn, logf logger.Logf, extend func()) {
	if debugNetstack() {
		logf("[v2] netstack: startPacketCopy to %v (%T) from %T", dstAddr, dst, src)
	}
	go func() {
		defer cancel() // tear down the other direction's copy

		bufp := udpBufPool.Get().(*[]byte)
		defer udpBufPool.Put(bufp)
		pkt := *bufp

		for {
			select {
			case <-ctx.Done():
				return
			default:
				n, srcAddr, err := src.ReadFrom(pkt)
				if err != nil {
					if ctx.Err() == nil {
						logf("read packet from %s failed: %v", srcAddr, err)
					}
					return
				}
				_, err = dst.WriteTo(pkt[:n], dstAddr)
				if err != nil {
					if ctx.Err() == nil {
						logf("write packet to %s failed: %v", dstAddr, err)
					}
					return
				}
				if debugNetstack() {
					logf("[v2] wrote UDP packet %s -> %s", srcAddr, dstAddr)
				}
				extend()
			}
		}
	}()
}

func stringifyTEI(tei stack.TransportEndpointID) string {
	localHostPort := net.JoinHostPort(tei.LocalAddress.String(), strconv.Itoa(int(tei.LocalPort)))
	remoteHostPort := net.JoinHostPort(tei.RemoteAddress.String(), strconv.Itoa(int(tei.RemotePort)))
	return fmt.Sprintf("%s -> %s", remoteHostPort, localHostPort)
}

func ipPortOfNetstackAddr(a tcpip.Address, port uint16) (ipp netip.AddrPort, ok bool) {
	if addr, ok := netip.AddrFromSlice(a.AsSlice()); ok {
		return netip.AddrPortFrom(addr, port), true
	}
	return netip.AddrPort{}, false
}



// windowsPingOutputIsSuccess reports whether the ping.exe output b contains a
// success ping response for ip.
//
// See https://github.com/tailscale/tailscale/issues/13654
//
// TODO(bradfitz,nickkhyl): delete this and use the proper Windows APIs.
func windowsPingOutputIsSuccess(ip netip.Addr, b []byte) bool {
	// Look for a line that contains " <ip>: " and then three equal signs.
	// As a special case, the 2nd equal sign may be a '<' character
	// for sub-millisecond pings.
	// This heuristic seems to match the ping.exe output in any language.
	sub := fmt.Appendf(nil, " %s: ", ip)

	eqSigns := func(bb []byte) (n int) {
		for _, b := range bb {
			if b == '=' || (b == '<' && n == 1) {
				n++
			}
		}
		return
	}

	for len(b) > 0 {
		var line []byte
		line, b, _ = bytes.Cut(b, []byte("\n"))
		if _, rest, ok := bytes.Cut(line, sub); ok && eqSigns(rest) == 3 {
			return true
		}
	}
	return false
}
