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
//	--genkey FILE write a fresh unencrypted ed25519 SSH private key to FILE (mode 0600)
//	              and exit — generated at plant time so no key is ever committed
//	--map FILE    map FILE read+exec into this process, as a loaded shared library
//	              (process-library-from-writable-path / process-library-deleted)
//	--spawn-shell start a real /bin/sh child (left running, this process's direct
//	              child per the OS, not just a spoofed argv) and keep sleeping
//	              (shell-child-of-web-server: this binary is copied to a path
//	              ending in a web-server name, e.g. .../nginx, as the "parent")
//	(anything else / none) just sleep — for deleted/world-writable/masquerade/
//	                        empty-environ/reverse-shell/ssh-tunnel via spoofed exec
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"net"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
)

const holdFor = time.Hour // hold the resource well past a scan; the orchestrator kills us

func main() {
	listen, connect, packet, memfd, spawnShell := 0, 0, false, false, false
	mapFile := ""
	args := os.Args[1:]
	for i := 0; i < len(args); i++ {
		if args[i] == "--genkey" && i+1 < len(args) {
			os.Exit(genKey(args[i+1]))
		}
	}
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
		case "--spawn-shell":
			spawnShell = true
		case "--map":
			if i+1 < len(args) {
				i++
				mapFile = args[i]
			}
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
	if mapFile != "" {
		mapExecutable(mapFile)
	}
	if spawnShell {
		spawnChildShell()
	}
	if packet {
		if fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL))); err == nil {
			defer unix.Close(fd)
		}
	}
	time.Sleep(holdFor)
}

// spawnChildShell starts a real /bin/sh that outlives this call, as this process's
// direct OS child (shell-child-of-web-server: this binary is copied to a path
// ending in a web-server name, so its own /proc/PID/exe is what the rule's parent
// lookup matches). Best-effort: a failure here just leaves nothing to detect,
// same as any other technique whose prerequisite (a shell, here) is missing.
func spawnChildShell() {
	cmd := exec.Command("/bin/sh", "-c", "sleep "+strconv.Itoa(int(holdFor.Seconds())))
	// Pdeathsig so cleanup (which only kills this process, not a tree) doesn't
	// orphan the child onto PID 1 for the rest of holdFor.
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	_ = cmd.Start()
}

// mapExecutable maps the first page of a file read+exec, which is what the dynamic
// linker does for a loaded library: /proc/PID/maps then lists the file with an r-x
// mapping. The mapping is kept for the life of the process. A noexec filesystem refuses
// PROT_EXEC; the technique then simply goes undetected there, as it would for an attacker.
func mapExecutable(path string) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }() // the mapping outlives the descriptor
	_, _ = syscall.Mmap(int(f.Fd()), 0, os.Getpagesize(), syscall.PROT_READ|syscall.PROT_EXEC, syscall.MAP_PRIVATE)
}

// genKey writes a throwaway ed25519 private key in the OpenSSH format, unencrypted.
func genKey(path string) int {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return 1
	}
	block, err := ssh.MarshalPrivateKey(priv, "bladedr-poligon")
	if err != nil {
		return 1
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		return 1
	}
	return 0
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
