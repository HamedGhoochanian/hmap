package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	//"./known"
	"golang.org/x/sync/semaphore"
)

const (
	colorRed   = "\033[31m"
	colorGreen = "\033[32m"
	colorCyan  = "\033[36m"
)

type PortScanner struct {
	ip   string
	lock *semaphore.Weighted
}

func (ps *PortScanner) StartRange(f, l int, timeout time.Duration, printClosed bool) {
	wg := sync.WaitGroup{}
	defer wg.Wait()

	for port := f; port <= l; port++ {
		_ = ps.lock.Acquire(context.TODO(), 1)
		wg.Add(1)
		go func(port int) {
			defer ps.lock.Release(1)
			defer wg.Done()
			res := ScanPort(ps.ip, port, timeout, printClosed)
			if res {
				fmt.Println(string(colorCyan), "port", port, string(colorGreen), "is open")
			} else if printClosed {
				fmt.Println(string(colorCyan), "port", port, string(colorRed), "is closed")
			}
		}(port)
	}
}

func (ps *PortScanner) StartMap(list map[int]string, timeout time.Duration, printClosed bool) {
	wg := sync.WaitGroup{}
	defer wg.Wait()
	for port, name := range list {
		_ = ps.lock.Acquire(context.TODO(), 1)
		wg.Add(1)
		go func(port int, name string) {
			defer ps.lock.Release(1)
			defer wg.Done()
			res := ScanPort(ps.ip, port, timeout, printClosed)
			if res {
				fmt.Println(string(colorCyan), "port", port, "of service", name, string(colorGreen), "is open")
			} else {
				fmt.Println(string(colorCyan), "port", port, "of service", name, string(colorRed), "is closed")
			}
		}(port, name)
	}
}

func GetSystemMaxFile() int64 {
	out, err := exec.Command("/bin/sh", "-c", "ulimit -n").Output()
	if err != nil {
		panic(err)
	}
	max, err := strconv.ParseInt(strings.TrimSpace(string(out)), 10, 64)
	if err != nil {
		panic(err)
	}
	return max
}

func ScanPort(ip string, port int, timeout time.Duration, printClosed bool) bool {
	target := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", target, timeout)
	if err != nil {
		if strings.Contains(err.Error(), "too many open files") {
			time.Sleep(timeout)
			ScanPort(ip, port, timeout, printClosed)
		} else {
			return false
		}
		return false
	}
	_ = conn.Close()
	return true
}

var reservedPorts = map[int]string{
	27017: "mongodb [ http://www.mongodb.org/ ]",
	28017: "mongodb web admin [ http://www.mongodb.org/ ]",
	21:    "ftp",
	22:    "SSH",
	23:    "telnet",
	25:    "SMTP",
	66:    "Oracle SQL*NET?",
	69:    "tftp",
	80:    "http",
	88:    "kerberos",
	109:   "pop2",
	110:   "pop3",
	123:   "ntp",
	137:   "netbios",
	139:   "netbios",
	443:   "https",
	445:   "Samba",
	631:   "cups",
	5800:  "VNC remote desktop",
	194:   "IRC",
	118:   "SQL service?",
	150:   "SQL-net?",
	1433:  "Microsoft SQL server",
	1434:  "Microsoft SQL monitor",
	3306:  "MySQL",
	3396:  "Novell NDPS Printer Agent",
	3535:  "SMTP (alternate)",
	554:   "RTSP",
	9160:  "Cassandra [ http://cassandra.apache.org/ ]",
}

var appLayerPorts = map[int]string{
	80:   "HTTP",
	21:   "FTP",
	22:   "SSH",
	23:   "TELNET",
	25:   "SMTP",
	443:  "https",
	3535: "SMTP (alternate)",
	554:  "RTSP",
}

func main() {
	first := flag.Int("f", 1, "Starting port for scanning, 1 by default")
	last := flag.Int("l", 65535, "end port for scanning, 65535 by default")
	app := flag.Bool("app", false, "only scan app layer ports")
	reserved := flag.Bool("reserved", false, "only scan famous reserved ports")
	timeout := flag.Int("timeout", 500, "connection timeout, default 500")
	ip := flag.String("ip", "127.0.0.1", "sniffing target")
	printClosed := flag.Bool("printClosed", false, "print closed ports during range sniffing")
	flag.Parse()
	ps := &PortScanner{ip: *ip, lock: semaphore.NewWeighted(GetSystemMaxFile())}
	if *app {
		ps.StartMap(appLayerPorts, time.Duration(*timeout), true)
	} else if *reserved {
		ps.StartMap(reservedPorts, time.Duration(*timeout)*time.Millisecond, *printClosed)
	} else {
		ps.StartRange(*first, *last, time.Duration(*timeout)*time.Millisecond, *printClosed)
	}
}
