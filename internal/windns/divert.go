package windns

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

type Address struct {
	Timestamp int64
	Flags     uint32
	Reserved2 uint32
	Data      [64]byte
}

const (
	LayerNetwork = 0
	FlagOutbound = 1 << 17
	FlagIPv6     = 1 << 20

	DefaultDoH = "https://cloudflare-dns.com/dns-query"

	ParamQueueLen  = 0
	ParamQueueTime = 1
	ParamQueueSize = 2
)

var packetPool = sync.Pool{
	New: func() any {
		return make([]byte, 65535)
	},
}

type cacheEntry struct {
	resp []byte
	exp  time.Time
}

type Diverter struct {
	mu          sync.Mutex
	dll         *syscall.LazyDLL
	procOpen    *syscall.LazyProc
	procClose   *syscall.LazyProc
	procRecv    *syscall.LazyProc
	procSend    *syscall.LazyProc
	procCalcCk  *syscall.LazyProc
	procSetParam *syscall.LazyProc

	handle uintptr
	cancel context.CancelFunc
	client *http.Client
	dohURL string

	cacheMu sync.RWMutex
	cache   map[string]cacheEntry
}

func New(dllDir string, dohURL string) (*Diverter, error) {
	if dohURL == "" {
		dohURL = DefaultDoH
	}
	dllPath := filepath.Join(dllDir, "WinDivert.dll")
	dll := syscall.NewLazyDLL(dllPath)

	// Custom Transport that pins known DoH servers to literal IPs,
	// completely eliminating OS port 53 DNS recursion deadlock.
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			target := addr
			if strings.HasPrefix(addr, "cloudflare-dns.com:") {
				target = "1.1.1.1:443"
			} else if strings.HasPrefix(addr, "dns.google:") {
				target = "8.8.8.8:443"
			} else if strings.HasPrefix(addr, "dns.adguard-dns.com:") {
				target = "94.140.14.14:443"
			} else if strings.HasPrefix(addr, "dns.quad9.net:") {
				target = "9.9.9.9:443"
			}
			dialer := &net.Dialer{Timeout: 3 * time.Second}
			return dialer.DialContext(ctx, network, target)
		},
		TLSClientConfig: &tls.Config{
			ServerName: "cloudflare-dns.com",
		},
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 50,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression: true,
		ForceAttemptHTTP2:   true,
	}

	return &Diverter{
		dll:          dll,
		procOpen:     dll.NewProc("WinDivertOpen"),
		procClose:    dll.NewProc("WinDivertClose"),
		procRecv:     dll.NewProc("WinDivertRecv"),
		procSend:     dll.NewProc("WinDivertSend"),
		procCalcCk:   dll.NewProc("WinDivertHelperCalcChecksums"),
		procSetParam: dll.NewProc("WinDivertSetParam"),
		dohURL:       dohURL,
		client: &http.Client{
			Timeout:   3 * time.Second,
			Transport: transport,
		},
		cache: make(map[string]cacheEntry),
	}, nil
}

func (d *Diverter) Start(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.handle != 0 {
		return nil
	}

	filter, err := syscall.BytePtrFromString("outbound and (udp.DstPort == 53 or udp.DstPort == 443) and !loopback")
	if err != nil {
		return err
	}

	// layer=0 (Network), priority=500, flags=0
	h, _, openErr := d.procOpen.Call(uintptr(unsafe.Pointer(filter)), LayerNetwork, 500, 0)
	if h == ^uintptr(0) || h == 0 {
		return fmt.Errorf("windivert open: %w", openErr)
	}
	d.handle = h

	// Optimize driver queue length & memory to prevent dropped packets under heavy load
	d.procSetParam.Call(h, ParamQueueLen, 8192)
	d.procSetParam.Call(h, ParamQueueSize, 16*1024*1024)

	runCtx, cancel := context.WithCancel(ctx)
	d.cancel = cancel

	go d.loop(runCtx)
	return nil
}

func (d *Diverter) Stop() {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.cancel != nil {
		d.cancel()
		d.cancel = nil
	}
	if d.handle != 0 {
		d.procClose.Call(d.handle)
		d.handle = 0
	}
}

func (d *Diverter) loop(ctx context.Context) {
	packet := make([]byte, 65535)
	var recvLen uint32
	var addr Address

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		r1, _, _ := d.procRecv.Call(
			d.handle,
			uintptr(unsafe.Pointer(&packet[0])),
			uintptr(len(packet)),
			uintptr(unsafe.Pointer(&recvLen)),
			uintptr(unsafe.Pointer(&addr)),
		)
		if r1 == 0 {
			// Handle closed or interrupted
			return
		}

		// Concurrently handle packet with buffer pooling:
		// main WinDivert loop never stalls on HTTP/2 network I/O
		buf := packetPool.Get().([]byte)
		copy(buf[:recvLen], packet[:recvLen])
		addrCopy := addr
		go func(p []byte, a Address) {
			defer packetPool.Put(p)
			d.handlePacket(p, a)
		}(buf[:recvLen], addrCopy)
	}
}

func (d *Diverter) handlePacket(packet []byte, addr Address) {
	isIPv6 := (addr.Flags & FlagIPv6) != 0

	// Drop UDP 443 (QUIC) for IPv6
	if isIPv6 && len(packet) >= 48 {
		if packet[6] == 17 { // UDP
			dstPort := binary.BigEndian.Uint16(packet[42:44])
			if dstPort == 443 {
				// Silently drop QUIC initial to force TCP fallback
				return
			}
		}
	}

	// Handle IPv4 UDP
	if !isIPv6 && len(packet) >= 28 {
		ihl := int(packet[0]&0x0F) * 4
		if len(packet) >= ihl+8 {
			srcPort := binary.BigEndian.Uint16(packet[ihl : ihl+2])
			dstPort := binary.BigEndian.Uint16(packet[ihl+2 : ihl+4])
			udpLen := int(binary.BigEndian.Uint16(packet[ihl+4 : ihl+6]))

			// Drop UDP 443 (QUIC) to force TCP fallback
			if dstPort == 443 {
				return
			}

			if dstPort == 53 && udpLen >= 8 && len(packet) >= ihl+udpLen {
				dnsQuery := packet[ihl+8 : ihl+udpLen]

				// Forward via DoH
				dnsResp, err := d.resolveDoH(dnsQuery)
				if err == nil && len(dnsResp) > 0 {
					// Craft response packet
					newTotalLen := ihl + 8 + len(dnsResp)
					respPacket := make([]byte, newTotalLen)

					// Copy IP header
					copy(respPacket[:ihl], packet[:ihl])
					// Swap IP addresses (src <-> dst)
					copy(respPacket[12:16], packet[16:20])
					copy(respPacket[16:20], packet[12:16])
					// Update total length
					binary.BigEndian.PutUint16(respPacket[2:4], uint16(newTotalLen))

					// Copy UDP header
					// Swap ports
					binary.BigEndian.PutUint16(respPacket[ihl:ihl+2], 53)
					binary.BigEndian.PutUint16(respPacket[ihl+2:ihl+4], srcPort)
					// Update UDP length
					binary.BigEndian.PutUint16(respPacket[ihl+4:ihl+6], uint16(8+len(dnsResp)))
					// Clear checksum before calc
					binary.BigEndian.PutUint16(respPacket[ihl+6:ihl+8], 0)

					// Copy DNS payload
					copy(respPacket[ihl+8:], dnsResp)

					// Convert address to inbound
					respAddr := addr
					respAddr.Flags &= ^uint32(FlagOutbound)

					// Calculate checksums
					d.procCalcCk.Call(
						uintptr(unsafe.Pointer(&respPacket[0])),
						uintptr(len(respPacket)),
						uintptr(unsafe.Pointer(&respAddr)),
						0,
					)

					// Send response back to OS stack
					var sendLen uint32
					d.procSend.Call(
						d.handle,
						uintptr(unsafe.Pointer(&respPacket[0])),
						uintptr(len(respPacket)),
						uintptr(unsafe.Pointer(&sendLen)),
						uintptr(unsafe.Pointer(&respAddr)),
					)
					return
				}
			}
		}
	}

	// Fallback: pass original packet unmodified so normal network doesn't break
	var sendLen uint32
	d.procSend.Call(
		d.handle,
		uintptr(unsafe.Pointer(&packet[0])),
		uintptr(len(packet)),
		uintptr(unsafe.Pointer(&sendLen)),
		uintptr(unsafe.Pointer(&addr)),
	)
}

func (d *Diverter) resolveDoH(dnsQuery []byte) ([]byte, error) {
	if len(dnsQuery) < 12 {
		return nil, fmt.Errorf("dns query too short")
	}
	queryID := binary.BigEndian.Uint16(dnsQuery[0:2])
	cacheKey := string(dnsQuery[12:]) // exact QNAME + QTYPE + QCLASS section (independent of transaction ID and flags)

	// 1. Check in-memory RAM cache
	d.cacheMu.RLock()
	entry, hit := d.cache[cacheKey]
	d.cacheMu.RUnlock()

	if hit && time.Now().Before(entry.exp) {
		// Instant 0ms cache hit: clone response and overwrite with current query ID
		cloned := make([]byte, len(entry.resp))
		copy(cloned, entry.resp)
		binary.BigEndian.PutUint16(cloned[0:2], queryID)
		return cloned, nil
	}

	req, err := http.NewRequestWithContext(context.Background(), "POST", d.dohURL, bytes.NewReader(dnsQuery))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	resp, err := d.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("doh status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// 2. Cache valid response for 90 seconds
	if len(body) >= 12 {
		d.cacheMu.Lock()
		if len(d.cache) > 2000 {
			d.cache = make(map[string]cacheEntry)
		}
		d.cache[cacheKey] = cacheEntry{
			resp: body,
			exp:  time.Now().Add(90 * time.Second),
		}
		d.cacheMu.Unlock()
	}

	return body, nil
}
