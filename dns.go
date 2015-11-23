package multidns

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"
	"net"

	"strings"
	"time"
	"unsafe"

	"github.com/pmylund/go-cache"
)

const (
	// dnsHeader.flags
	_QR = 1 << 15 // query/response (response=1)
	_AA = 1 << 10 // authoritative
	_TC = 1 << 9  // truncated
	_RD = 1 << 8  // recursion desired
	_RA = 1 << 7  // recursion available
	//question type
	qdTypeA     = 1
	qdTypeCNAME = 5
	//question class
	qdClassIN  = 1
	qdClassAny = 255

	namePtrFlag uint8 = 0xc0

	nameLenMax = 63

	dnsRespMax = 1024
	dnsBufSize = 2048
	//question ptr compress method
	qdNormal    = 0
	qdCompress1 = 1 //for google dns and opendns
	qdCompress2 = 2 //google dns only
	//timeout
	dnsTimeout = time.Second * 1
)

var qdCompressMap = map[string]int{
	"8.8.4.4:53":          qdCompress2,
	"8.8.8.8:53":          qdCompress2,
	"208.67.222.222:53":   qdCompress1,
	"208.67.222.222:5353": qdCompress1,
	"208.67.220.220:53":   qdCompress1,
	"208.67.220.220:5353": qdCompress1,
}

//error
var (
	nameFomatError     = errors.New("Wrong name format")
	nameLargeError     = errors.New("Name too large")
	qdGenError         = errors.New("DNS question gen failed")
	reqNetworkError    = errors.New("DNS question network error")
	respNetworkError   = errors.New("DNS response network error")
	respFormatError    = errors.New("DNS response format error")
	respNotFoundError  = errors.New("DNS resove failed")
	dnsTimeoutError    = errors.New("DNS resove timeout")
	dnsNoServerError   = errors.New("DNS server not configure")
	dnsServerAddrError = errors.New("DNS server addr format error")
)

type dnsHeader struct {
	Id      uint16
	Flags   uint16
	QdCount uint16
	AnCount uint16
	NsCount uint16
	ArCount uint16
}

//question
type qdHeader struct {
	name    []byte
	qdType  uint16
	qdClass uint16
}

var addrs []*net.UDPAddr
var badIPMap map[uint32]bool
var checkBadResp = false
var badIPs = []uint32{
	0x76053106, 0x80797e8b, 0x9f6a794b, 0xa9840d67,
	0xbc050460, 0xbda31105, 0xc043c606, 0xc504040c,
	0xca6a0102, 0xcab50755, 0xcba1e6ab, 0xcb620741,
	0xcf0c5862, 0xd0381f2b, 0xd1913632, 0xd1dc1eae,
	0xd1244921, 0xd155e58a, 0xd35e4293, 0xd5a9fb23,
	0xd8ddbcb6, 0xd8eab30d, 0x1759053c, 0xf3b9bb27,
	0xf9812e30, 0xfd9d0ea5, 0x253d369e, 0x042442b2,
	0x2e52ae44, 0x31027b38, 0x364c8701, 0x3b1803ad,
	0x402158a1, 0x4021632f, 0x4042a3fb, 0x4168cafc,
	0x41a0db71, 0x422dfced, 0x480ecd68, 0x480ecd63,
	0x4a7d7f66, 0x4a7d9b66, 0x4a7d2766, 0x4a7d2771,
	0x4d04075c, 0x4e10310f, 0x0807c62d, 0x5d2e0859,
	0xcc0dfa22, 0xcc0dfb22, 0xd04e4622, 0xd04e4722,
}

var dnsCache *cache.Cache

func init() {
	rand.Seed(time.Now().Unix())
	dnsCache = cache.New(time.Hour, time.Minute)
}

func nameQdTrans(name string) ([]byte, error) {
	n := len(name)
	ret := make([]byte, n+1, n+2)
	pos := -1
	count := 0
	for i := 0; i < n; i++ {
		if name[i] == '.' {
			if count == 0 {
				return ret, nameFomatError
			} else if count > nameLenMax {
				return ret, nameLargeError
			}
			ret[pos+1] = uint8(count)
			pos = i
			count = 0
		} else {
			count += 1
			ret[i+1] = name[i]
		}
	}
	ret[pos+1] = uint8(count)
	if ret[n] != 0 {
		ret = append(ret, 0)
	}
	return ret, nil
}

func dnsQdGen(name, remote string) ([]byte, error) {
	nameBytes, err := nameQdTrans(name)
	if err != nil {
		return []byte{}, err
	}
	dns := dnsHeader{
		Id:      uint16(rand.Uint32() & 0xffff),
		Flags:   _RD, //recursion desired
		QdCount: 1,
	}

	buf := bytes.Buffer{}
	err = binary.Write(&buf, binary.BigEndian, dns)
	if err != nil {
		return []byte{}, qdGenError
	}

	qd := qdHeader{
		name:    nameBytes,
		qdType:  qdTypeA,
		qdClass: qdClassIN,
	}

	compress, _ := qdCompressMap[remote]

	switch compress {
	case qdCompress1:
		n := len(qd.name)
		if qd.name[n-1] == 0 {
			qd.name[n-1] = 0xc0
			rnd := uint8(rand.Intn(4)*2 + 4) //4, 6, 8, 10
			qd.name = append(qd.name, rnd)
		}
		binary.Write(&buf, binary.BigEndian, qd.name)
		binary.Write(&buf, binary.BigEndian, qd.qdType)
		binary.Write(&buf, binary.BigEndian, qd.qdClass)
		break
	case qdCompress2:
		rnd := uint8(rand.Intn(5) + 4) //4-8
		var pos uint8 = 12 + 2 + 2 + 2 + rnd
		binary.Write(&buf, binary.BigEndian, namePtrFlag)
		binary.Write(&buf, binary.BigEndian, pos)
		binary.Write(&buf, binary.BigEndian, qd.qdType)
		binary.Write(&buf, binary.BigEndian, qd.qdClass)
		for i := 0; uint8(i) < rnd; i++ {
			binary.Write(&buf, binary.BigEndian, uint8(rand.Uint32()))
		}
		binary.Write(&buf, binary.BigEndian, qd.name)
		break
	default:
		binary.Write(&buf, binary.BigEndian, qd.name)
		binary.Write(&buf, binary.BigEndian, qd.qdType)
		binary.Write(&buf, binary.BigEndian, qd.qdClass)
	}
	return buf.Bytes(), nil
}

func parseNameSize(buf []byte, pos int) (size int) {
	for {
		n := int(buf[pos])
		if n == 0 {
			size += 1
			return
		} else if n == int(namePtrFlag) {
			size += 2
			return
		} else if n > nameLenMax {
			return -1
		}
		size += (n + 1)
		pos += (n + 1)
		if pos >= dnsRespMax {
			return -1
		}
	}
	return
}

func dnsReqResp(name string, conn *net.UDPConn) (net.IP, error) {
	//question
	var ret net.IP
	remote := conn.RemoteAddr().String()
	header, err := dnsQdGen(name, remote)
	if err != nil {
		return ret, qdGenError
	}
	_, err = conn.Write(header)
	if err != nil {
		return ret, reqNetworkError
	}

	respBuf := make([]byte, dnsBufSize)
	nread, _, err := conn.ReadFromUDP(respBuf[:dnsRespMax])

	if err != nil {
		return ret, respNetworkError
	}
	//respose
	respRd := bytes.NewReader(respBuf)

	dns := dnsHeader{}
	err = binary.Read(respRd, binary.BigEndian, &dns)
	if (dns.Flags&_QR) == 0 || err != nil {
		return ret, respFormatError
	}
	numQd := dns.QdCount
	numAn := dns.AnCount

	buflen := len(respBuf)
	pos := int(unsafe.Sizeof(dns))
	for i := 0; i < int(numQd); i++ {
		for {
			n := int(respBuf[pos])
			if n == 0 {
				pos += 1
				break
			}
			if n > nameLenMax {
				return ret, respFormatError
			}
			pos += (n + 1)
			if pos >= buflen {
				return ret, respFormatError
			}
		}
		pos += 4 //skip type and class
	}

	if pos >= nread {
		return ret, respFormatError
	}

	for i := 0; i < int(numAn); i++ {
		size := parseNameSize(respBuf, pos)
		if size <= 0 {
			return ret, respFormatError
		}
		pos += size

		tp := (respBuf[pos] << 16) + respBuf[pos+1]
		pos += 8 //skip type, class ttl
		if pos >= nread {
			return ret, respFormatError
		}
		dataLen := (respBuf[pos] << 16) + respBuf[pos+1]
		pos += 2 //skip data len
		if tp == qdTypeA && dataLen == net.IPv4len {
			ret = respBuf[pos : pos+4]
			return ret, nil
		}
		pos += int(dataLen) //skip data
		if pos >= nread {
			return ret, respFormatError
		}
	}
	return ret, respNotFoundError
}

func resolve(name string, conn *net.UDPConn, chn chan<- []byte) {
	ip, err := dnsReqResp(name, conn)
	if err != nil {
		return
	}
	chn <- ip
}

func DNSInit(servers []string) error {
	if len(addrs) != 0 {
		addrs = make([]*net.UDPAddr, 0)
	}

	n := len(servers)
	for i := 0; i < n; i++ {
		if strings.Index(servers[i], ":") < 0 {
			servers[i] = fmt.Sprintf("%s:%d", servers[i], 53)
		}
	}
	for i := 0; i < n; i++ {
		raddr, err := net.ResolveUDPAddr("udp", servers[i])
		if err != nil {
			continue
		}
		addrs = append(addrs, raddr)
	}

	if badIPMap == nil {
		badIPMap = make(map[uint32]bool)
		for _, ipLong := range badIPs {
			badIPMap[ipLong] = true
		}
	}
	if len(addrs) == 0 {
		return dnsServerAddrError
	}
	for _, addr := range addrs {
		if _, ok := qdCompressMap[addr.String()]; ok {
			checkBadResp = true
		}
	}
	return nil
}

func DNSQuery(name string) (net.IP, error) {
	if v, ok := dnsCache.Get(name); ok {
		if ip, ok := v.([]byte); ok && len(ip) == net.IPv4len {
			return ip, nil
		}
	}
	n := len(addrs)
	if n == 0 {
		return net.IP{}, dnsNoServerError
	}
	conns := make([]*net.UDPConn, 0, n)
	for i := 0; i < n; i++ {
		conn, err := net.DialUDP("udp", nil, addrs[i])
		if err != nil {
			continue
		}
		err = conn.SetDeadline(time.Now().Add(dnsTimeout))
		if err != nil {
			conn.Close()
			continue
		}
		conns = append(conns, conn)
	}

	defer func(conns []*net.UDPConn) {
		for _, conn := range conns {
			conn.Close()
		}
	}(conns)
	n = len(conns)
	chn := make(chan []byte, n)
	for i := 0; i < n; i++ {
		go resolve(name, conns[i], chn)
	}

	timeleft := dnsTimeout
	for i := 0; i < n; i++ {
		t := time.Now()
		select {
		case <-time.After(timeleft):
			return net.IP{}, dnsTimeoutError
		case ip := <-chn:
			if checkBadResp {
				ipLong := (uint32)(ip[0])<<24 + (uint32)(ip[1])<<16 + (uint32)(ip[2])<<8 + (uint32)(ip[3])
				if badIPMap[ipLong] {
					timeleft -= time.Now().Sub(t)
					//fmt.Println("bad ip, timeleft", timeleft)
					if timeleft <= 0 {
						return net.IP{}, dnsTimeoutError
					}
					continue
				}
			}
			dnsCache.Add(name, ip, cache.DefaultExpiration)
			return ip, nil
		}
	}
	return net.IP{}, dnsTimeoutError
}
