// Copyright (c) 2026 allddd <me@allddd.onl>
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

package tui

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/charmbracelet/x/exp/golden"
	"github.com/charmbracelet/x/vt"
	"github.com/charmbracelet/x/xpty"
	"gitlab.com/allddd/opnsense-filterlog/internal/meta"
)

const (
	down   = "\x1b[B"
	end    = "\x1b[F"
	enter  = "\r"
	escape = "\x1b"
	home   = "\x1b[H"
	left   = "\x1b[D"
	pgDown = "\x1b[6~"
	pgUp   = "\x1b[5~"
	right  = "\x1b[C"
	up     = "\x1b[A"
)

type pty struct {
	cmd  *exec.Cmd
	em   *vt.Emulator
	mu   sync.Mutex
	t    *testing.T
	term xpty.Pty
}

func initPTY(t *testing.T, path string, width, height int) *pty {
	t.Helper()
	term, err := xpty.NewPty(width, height)
	if err != nil {
		t.Skip(err)
	}
	em := vt.NewEmulator(width, height)
	cmd := exec.CommandContext(context.Background(), "../../"+meta.Name, path)
	cmd.Env = append(os.Environ(), "TERM=xterm-256color")
	if err := term.Start(cmd); err != nil {
		term.Close()
		em.Close()
		t.Fatal(err)
	}
	p := &pty{
		cmd:  cmd,
		em:   em,
		t:    t,
		term: term,
	}
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := term.Read(buf)
			if n > 0 {
				p.mu.Lock()
				p.em.Write(buf[:n])
				p.mu.Unlock()
			}
			if err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() {
		_ = p.cmd.Process.Kill()
		_ = p.cmd.Wait()
		term.Close()
		em.Close()
	})
	return p
}

func (p *pty) screen() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.em.String()
}

func (p *pty) send(input string) {
	p.t.Helper()
	if _, err := p.term.Write([]byte(input)); err != nil {
		p.t.Fatal(err)
	}
}

func (p *pty) wait(text string) {
	p.t.Helper()
	timeout := time.After(2 * time.Second)
	for {
		select {
		case <-timeout:
			p.t.Fatalf("timeout waiting for %q\nscreen:\n%s", text, p.screen())
		default:
		}
		if strings.Contains(p.screen(), text) {
			time.Sleep(100 * time.Millisecond)
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func (p *pty) resize(width, height int) {
	p.t.Helper()
	if err := p.term.Resize(width, height); err != nil {
		p.t.Fatal(err)
	}
	p.mu.Lock()
	p.em.Close()
	p.em = vt.NewEmulator(width, height)
	p.mu.Unlock()
	_ = p.cmd.Process.Signal(syscall.SIGWINCH)
}

func check(t *testing.T, p *pty, name string) {
	t.Helper()
	t.Run(name, func(t *testing.T) {
		t.Helper()
		golden.RequireEqual(t, []byte(p.screen()))
	})
}

func TestNoValidEntries(t *testing.T) {
	p := initPTY(t, "/dev/null", 80, 10)
	p.wait("no valid entries")
	golden.RequireEqual(t, []byte(p.screen()))
}

func TestNormal(t *testing.T) {
	p := initPTY(t, "../stream/testdata/valid.log", 120, 24)
	p.wait("position:")

	check(t, p, "default")

	p.send("j")
	p.send(down)
	p.send("j")
	p.wait("position:")
	check(t, p, "scroll down")

	p.send("k")
	p.send(up)
	p.wait("position:")
	check(t, p, "scroll up")

	p.send("d")
	p.send(pgDown)
	p.wait("position:")
	check(t, p, "page down")

	p.send("u")
	p.send(pgUp)
	p.wait("position:")
	check(t, p, "page up")

	p.send(end)
	p.wait("position:")
	check(t, p, "jump to end")

	p.send(home)
	p.wait("position:")
	check(t, p, "jump to top")

	p.resize(80, 24)
	p.wait("position:")
	p.send(right)
	p.send("l")
	p.wait("position:")
	check(t, p, "horizontal scroll right")

	p.send("h")
	p.send(left)
	p.wait("position:")
	check(t, p, "horizontal scroll left")

	p.resize(120, 24)
	p.wait("position:")

	p.send(enter)
	p.wait("esc: back")
	check(t, p, "details")

	p.send("j")
	p.send(down)
	p.wait("esc: back")
	check(t, p, "details scroll")

	p.send("G")
	p.wait("esc: back")
	check(t, p, "details end")

	p.send(escape)
	p.wait("position:")
	check(t, p, "details back")

	p.send("/")
	time.Sleep(100 * time.Millisecond)
	p.send("invalid")
	time.Sleep(50 * time.Millisecond)
	p.send(escape)
	p.wait("position:")
	check(t, p, "filter cancel")

	p.send("/")
	time.Sleep(100 * time.Millisecond)
	p.send("proto tcp")
	time.Sleep(50 * time.Millisecond)
	p.send(enter)
	p.wait("position:")
	check(t, p, "filter apply")

	p.send(escape)
	p.wait("position:")
	check(t, p, "filter clear")

	p.send("/")
	time.Sleep(100 * time.Millisecond)
	p.send("proto and")
	time.Sleep(50 * time.Millisecond)
	p.send(enter)
	p.wait("position:")
	check(t, p, "filter invalid")

	p.send(escape)
	p.wait("position:")
	p.send("/")
	time.Sleep(100 * time.Millisecond)
	p.send("proto icmp")
	time.Sleep(50 * time.Millisecond)
	p.send(enter)
	p.wait("position:")
	check(t, p, "filter no matches")

	p.send(escape)
	p.wait("position:")
	check(t, p, "filter no matches clear")
}

func TestError(t *testing.T) {
	p := initPTY(t, "../stream/testdata/mixed.log", 120, 12)
	p.wait("position:")

	check(t, p, "default")

	p.send("e")
	p.wait("esc: back")
	check(t, p, "errors")

	p.send("j")
	p.send(down)
	p.wait("esc: back")
	check(t, p, "errors scroll")

	p.send(escape)
	p.wait("position:")
	check(t, p, "errors back")
}
