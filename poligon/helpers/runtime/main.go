//go:build linux

// Command bladedr-labhelper holds a runtime resource so the poligon can emulate a
// runtime technique while the probe scans, then sleeps until the orchestrator kills
// it. Modes (manual arg scan, so spoofed argv like "ssh -fND" or a reverse-shell
// string never cause a parse error — unknown args are ignored, and the process just
// sleeps, which is what the argv/filename/env-spoof techniques need):
//
//	--listen N    open a TCP listener on port N (suspicious-port-listener)
//	--connect N   listen on N and dial it on loopback, ESTABLISHED (miner-c2)
//	--packet      open an AF_PACKET raw socket (packet-sniffer-process)
//	--memfd       re-exec from an anonymous memfd (memfd-fileless-exec)
//	(anything else / none) just sleep — for deleted/world-writable/masquerade/
//	                        empty-environ/reverse-shell/ssh-tunnel via spoofed exec
package main

import (
	"net"
	"os"
	"strconv"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const holdFor = time.Hour // hold the resource well past a scan; the orchestrator kills us

func main() {
	listen, connect, packet, memfd := 0, 0, false, false
	args := os.Args[1:]
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--listen":
			listen = nextInt(args, &i)
		case "--connect":
			connect = nextInt(args, &i)
		case "--packet":
			packet = true
		case "--memfd":
			memfd = true
		}
	}

	if memfd {
		reExecFromMemfd() // replaces this process; returns only on failure
	}
	if listen > 0 {
		if ln, err := net.Listen("tcp", ":"+strconv.Itoa(listen)); err == nil {
			defer ln.Close()
			go acceptLoop(ln)
		}
	}
	if connect > 0 {
		if ln, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(connect)); err == nil {
			defer ln.Close()
			go acceptLoop(ln)
			if c, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(connect)); err == nil {
				defer c.Close()
			}
		}
	}
	if packet {
		if fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL))); err == nil {
			defer unix.Close(fd)
		}
	}
	time.Sleep(holdFor)
}

func nextInt(args []string, i *int) int {
	if *i+1 < len(args) {
		*i++
		n, _ := strconv.Atoi(args[*i])
		return n
	}
	return 0
}

// acceptLoop keeps accepting so a dialed connection stays ESTABLISHED.
func acceptLoop(ln net.Listener) {
	var held []net.Conn
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		held = append(held, c) // keep the server side open
	}
}

// reExecFromMemfd copies this binary into an anonymous memfd and execs it, so the
// resulting process's /proc/PID/exe points at /memfd: (deleted) — fileless exec.
func reExecFromMemfd() {
	self, err := os.ReadFile("/proc/self/exe")
	if err != nil {
		return
	}
	fd, err := unix.MemfdCreate("x", 0)
	if err != nil {
		return
	}
	for len(self) > 0 {
		n, err := unix.Write(fd, self)
		if err != nil {
			return
		}
		self = self[n:]
	}
	// execveat(fd, "", argv, env, AT_EMPTY_PATH) — x/sys has no wrapper in this
	// version, so call it directly. argv has no --memfd, so the child just sleeps.
	empty := bytePtr("")
	argv := []*byte{bytePtr("bladedr-labhelper"), nil}
	env := envPtrs()
	syscall.Syscall6(unix.SYS_EXECVEAT, uintptr(fd),
		uintptr(unsafe.Pointer(empty)),
		uintptr(unsafe.Pointer(&argv[0])),
		uintptr(unsafe.Pointer(&env[0])),
		uintptr(unix.AT_EMPTY_PATH), 0)
}

func bytePtr(s string) *byte { p, _ := syscall.BytePtrFromString(s); return p }

func envPtrs() []*byte {
	e := os.Environ()
	out := make([]*byte, 0, len(e)+1)
	for _, v := range e {
		out = append(out, bytePtr(v))
	}
	return append(out, nil) // null-terminated
}

func htons(p uint16) uint16 { return (p << 8) | (p >> 8) }
