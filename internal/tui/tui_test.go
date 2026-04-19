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
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/charmbracelet/x/exp/golden"
	"github.com/charmbracelet/x/vt"
	"github.com/charmbracelet/x/xpty"
	"gitlab.com/allddd/opnsense-filterlog/internal/meta"
)

type term struct {
	t     *testing.T
	cmd   *exec.Cmd
	pty   xpty.Pty
	vterm *vt.SafeEmulator
}

func newTerm(t *testing.T, path string, width, height int) *term {
	t.Helper()
	pty, err := xpty.NewPty(width, height)
	if err != nil {
		t.Skip(err)
	}
	vterm := vt.NewSafeEmulator(width, height)
	cmd := exec.CommandContext(context.Background(), "../../"+meta.Name, path)
	cmd.Env = append(os.Environ(), "TERM=xterm-256color")
	if err := pty.Start(cmd); err != nil {
		vterm.Close()
		pty.Close()
		t.Fatal(err)
	}
	p := &term{
		t:     t,
		cmd:   cmd,
		pty:   pty,
		vterm: vterm,
	}
	go io.Copy(vterm, pty)
	go io.Copy(pty, vterm)
	t.Cleanup(func() {
		_ = p.cmd.Process.Kill()
		_ = p.cmd.Wait()
		vterm.Close()
		pty.Close()
	})
	return p
}

func (p *term) wait(text string) {
	p.t.Helper()
	timeout := time.After(2 * time.Second)
	for {
		select {
		case <-timeout:
			p.t.Fatalf("timeout waiting for %q\nscreen:\n%s", text, p.vterm.String())
		default:
		}
		if strings.Contains(p.vterm.String(), text) {
			time.Sleep(100 * time.Millisecond)
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func (p *term) check(name string) {
	p.t.Helper()
	p.t.Run(name, func(t *testing.T) {
		t.Helper()
		golden.RequireEqual(t, []byte(p.vterm.String()))
	})
}

func TestNoValidEntries(t *testing.T) {
	p := newTerm(t, "/dev/null", 80, 10)
	p.wait("no valid entries")
	golden.RequireEqual(t, []byte(p.vterm.String()))
}

func TestNormal(t *testing.T) {
	p := newTerm(t, "../stream/testdata/valid.log", 100, 24)
	p.wait("position:")

	p.check("default")

	p.vterm.SendKey(vt.KeyPressEvent{Code: 'j'})
	p.vterm.SendKey(vt.KeyPressEvent{Code: vt.KeyDown})
	p.vterm.SendKey(vt.KeyPressEvent{Code: 'j'})
	p.wait("position:")
	p.check("scroll down")

	p.vterm.SendKey(vt.KeyPressEvent{Code: 'k'})
	p.vterm.SendKey(vt.KeyPressEvent{Code: vt.KeyUp})
	p.wait("position:")
	p.check("scroll up")

	p.vterm.SendKey(vt.KeyPressEvent{Code: 'd'})
	p.vterm.SendKey(vt.KeyPressEvent{Code: vt.KeyPgDown})
	p.wait("position:")
	p.check("page down")

	p.vterm.SendKey(vt.KeyPressEvent{Code: 'u'})
	p.vterm.SendKey(vt.KeyPressEvent{Code: vt.KeyPgUp})
	p.wait("position:")
	p.check("page up")

	p.vterm.SendKey(vt.KeyPressEvent{Code: vt.KeyEnd})
	p.wait("position:")
	p.check("jump to end")

	p.vterm.SendKey(vt.KeyPressEvent{Code: vt.KeyHome})
	p.wait("position:")
	p.check("jump to top")

	p.vterm.SendKey(vt.KeyPressEvent{Code: vt.KeyRight})
	p.vterm.SendKey(vt.KeyPressEvent{Code: 'l'})
	p.wait("position:")
	p.check("horizontal scroll right")

	p.vterm.SendKey(vt.KeyPressEvent{Code: 'h'})
	p.vterm.SendKey(vt.KeyPressEvent{Code: vt.KeyLeft})
	p.wait("position:")
	p.check("horizontal scroll left")

	p.vterm.SendKey(vt.KeyPressEvent{Code: vt.KeyEnter})
	p.wait("esc: back")
	p.check("details")

	p.vterm.SendKey(vt.KeyPressEvent{Code: 'j'})
	p.vterm.SendKey(vt.KeyPressEvent{Code: vt.KeyDown})
	p.wait("esc: back")
	p.check("details scroll")

	p.vterm.SendKey(vt.KeyPressEvent{Code: 'G'})
	p.wait("esc: back")
	p.check("details end")

	p.vterm.SendKey(vt.KeyPressEvent{Code: vt.KeyEscape})
	p.wait("position:")
	p.check("details back")

	p.vterm.SendKey(vt.KeyPressEvent{Code: '/'})
	time.Sleep(100 * time.Millisecond)
	p.vterm.SendText("invalid")
	time.Sleep(50 * time.Millisecond)
	p.vterm.SendKey(vt.KeyPressEvent{Code: vt.KeyEscape})
	p.wait("position:")
	p.check("filter cancel")

	p.vterm.SendKey(vt.KeyPressEvent{Code: '/'})
	time.Sleep(100 * time.Millisecond)
	p.vterm.SendText("proto tcp")
	time.Sleep(50 * time.Millisecond)
	p.vterm.SendKey(vt.KeyPressEvent{Code: vt.KeyEnter})
	p.wait("position:")
	p.check("filter apply")

	p.vterm.SendKey(vt.KeyPressEvent{Code: vt.KeyEscape})
	p.wait("position:")
	p.check("filter clear")

	p.vterm.SendKey(vt.KeyPressEvent{Code: '/'})
	time.Sleep(100 * time.Millisecond)
	p.vterm.SendText("proto and")
	time.Sleep(50 * time.Millisecond)
	p.vterm.SendKey(vt.KeyPressEvent{Code: vt.KeyEnter})
	p.wait("position:")
	p.check("filter invalid")

	p.vterm.SendKey(vt.KeyPressEvent{Code: vt.KeyEscape})
	p.wait("position:")
	p.vterm.SendKey(vt.KeyPressEvent{Code: '/'})
	time.Sleep(100 * time.Millisecond)
	p.vterm.SendText("proto icmp")
	time.Sleep(50 * time.Millisecond)
	p.vterm.SendKey(vt.KeyPressEvent{Code: vt.KeyEnter})
	p.wait("position:")
	p.check("filter no matches")

	p.vterm.SendKey(vt.KeyPressEvent{Code: vt.KeyEscape})
	p.wait("position:")
	p.check("filter no matches clear")
}

func TestError(t *testing.T) {
	p := newTerm(t, "../stream/testdata/mixed.log", 120, 12)
	p.wait("position:")

	p.check("default")

	p.vterm.SendKey(vt.KeyPressEvent{Code: 'e'})
	p.wait("esc: back")
	p.check("errors")

	p.vterm.SendKey(vt.KeyPressEvent{Code: 'j'})
	p.vterm.SendKey(vt.KeyPressEvent{Code: vt.KeyDown})
	p.wait("esc: back")
	p.check("errors scroll")

	p.vterm.SendKey(vt.KeyPressEvent{Code: vt.KeyEscape})
	p.wait("position:")
	p.check("errors back")
}
