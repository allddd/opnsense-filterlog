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

type terminal struct {
	t     *testing.T
	cmd   *exec.Cmd
	pty   xpty.Pty
	vterm *vt.SafeEmulator
}

func newTerminal(t *testing.T, width, height int, files ...string) *terminal {
	t.Helper()
	pty, err := xpty.NewPty(width, height)
	if err != nil {
		t.Fatal(err)
	}
	vterm := vt.NewSafeEmulator(width, height)
	cmd := exec.CommandContext(context.Background(), "../../"+meta.Name, files...)
	cmd.Env = append(os.Environ(), "TERM=xterm-256color")
	if err := pty.Start(cmd); err != nil {
		vterm.Close()
		pty.Close()
		t.Fatal(err)
	}
	term := &terminal{
		t:     t,
		cmd:   cmd,
		pty:   pty,
		vterm: vterm,
	}
	go io.Copy(vterm, pty)
	go io.Copy(pty, vterm)
	t.Cleanup(func() {
		_ = term.cmd.Process.Kill()
		_ = term.cmd.Wait()
		vterm.Close()
		pty.Close()
	})
	return term
}

func (term *terminal) wait(text string) {
	term.t.Helper()
	timeout := time.After(2 * time.Second)
	for {
		select {
		case <-timeout:
			term.t.Fatalf("timeout waiting for %q:\n\n%s", text, term.vterm.String())
		default:
		}
		if strings.Contains(term.vterm.String(), text) {
			time.Sleep(100 * time.Millisecond)
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func (term *terminal) check(name string) {
	term.t.Helper()
	term.t.Run(name, func(t *testing.T) {
		t.Helper()
		golden.RequireEqual(t, []byte(term.vterm.String()))
	})
}

func TestEmptyView(t *testing.T) {
	term := newTerminal(t, 80, 10, "/dev/null")
	term.wait("no valid entries")
	term.check("empty")
}

func TestDefaultDetailsErrorsView(t *testing.T) {
	term := newTerminal(t, 100, 24, "testdata/filter_20260726.log", "testdata/filter_20260727.log", "testdata/filter_20260728.log")
	term.wait("position:")
	term.check("default")

	term.vterm.SendKey(vt.KeyPressEvent{Code: 'j'})
	term.vterm.SendKey(vt.KeyPressEvent{Code: vt.KeyDown})
	term.vterm.SendKey(vt.KeyPressEvent{Code: 'j'})
	term.wait("position:")
	term.check("default scroll down")

	term.vterm.SendKey(vt.KeyPressEvent{Code: 'k'})
	term.vterm.SendKey(vt.KeyPressEvent{Code: vt.KeyUp})
	term.wait("position:")
	term.check("default scroll up")

	term.vterm.SendKey(vt.KeyPressEvent{Code: 'd'})
	term.vterm.SendKey(vt.KeyPressEvent{Code: vt.KeyPgDown})
	term.wait("position:")
	term.check("default page down")

	term.vterm.SendKey(vt.KeyPressEvent{Code: 'u'})
	term.vterm.SendKey(vt.KeyPressEvent{Code: vt.KeyPgUp})
	term.wait("position:")
	term.check("default page up")

	term.vterm.SendKey(vt.KeyPressEvent{Code: vt.KeyEnd})
	term.wait("position:")
	term.check("default jump to end")

	term.vterm.SendKey(vt.KeyPressEvent{Code: vt.KeyHome})
	term.wait("position:")
	term.check("default jump to top")

	term.vterm.SendKey(vt.KeyPressEvent{Code: vt.KeyRight})
	term.vterm.SendKey(vt.KeyPressEvent{Code: 'l'})
	term.wait("position:")
	term.check("default horizontal scroll right")

	term.vterm.SendKey(vt.KeyPressEvent{Code: 'h'})
	term.vterm.SendKey(vt.KeyPressEvent{Code: vt.KeyLeft})
	term.wait("position:")
	term.check("default horizontal scroll left")

	term.vterm.SendKey(vt.KeyPressEvent{Code: vt.KeyEnter})
	term.wait("esc: back")
	term.check("details")

	term.vterm.SendKey(vt.KeyPressEvent{Code: 'j'})
	term.vterm.SendKey(vt.KeyPressEvent{Code: vt.KeyDown})
	term.wait("esc: back")
	term.check("details scroll down")

	term.vterm.SendKey(vt.KeyPressEvent{Code: 'G'})
	term.wait("esc: back")
	term.check("details jump to end")

	term.vterm.SendKey(vt.KeyPressEvent{Code: vt.KeyEscape})
	term.wait("position:")
	term.check("details back")

	term.vterm.SendKey(vt.KeyPressEvent{Code: 'e'})
	term.wait("esc: back")
	term.check("errors")

	term.vterm.SendKey(vt.KeyPressEvent{Code: 'j'})
	term.vterm.SendKey(vt.KeyPressEvent{Code: vt.KeyDown})
	term.wait("esc: back")
	term.check("errors scroll down")

	term.vterm.SendKey(vt.KeyPressEvent{Code: 'G'})
	term.wait("esc: back")
	term.check("errors jump to end")

	term.vterm.SendKey(vt.KeyPressEvent{Code: vt.KeyEscape})
	term.wait("position:")
	term.check("errors back")

	term.vterm.SendKey(vt.KeyPressEvent{Code: '/'})
	time.Sleep(100 * time.Millisecond)
	term.vterm.SendText("invalid")
	time.Sleep(50 * time.Millisecond)
	term.vterm.SendKey(vt.KeyPressEvent{Code: vt.KeyEscape})
	term.wait("position:")
	term.check("filter cancel")

	term.vterm.SendKey(vt.KeyPressEvent{Code: '/'})
	time.Sleep(100 * time.Millisecond)
	term.vterm.SendText("proto gre")
	time.Sleep(50 * time.Millisecond)
	term.vterm.SendKey(vt.KeyPressEvent{Code: vt.KeyEnter})
	term.wait("position:")
	term.check("filter apply")

	term.vterm.SendKey(vt.KeyPressEvent{Code: vt.KeyEscape})
	term.wait("position:")
	term.check("filter clear")

	term.vterm.SendKey(vt.KeyPressEvent{Code: '/'})
	time.Sleep(100 * time.Millisecond)
	term.vterm.SendText("proto and")
	time.Sleep(50 * time.Millisecond)
	term.vterm.SendKey(vt.KeyPressEvent{Code: vt.KeyEnter})
	term.wait("position:")
	term.check("filter invalid")

	term.vterm.SendKey(vt.KeyPressEvent{Code: vt.KeyEscape})
	term.wait("position:")
	term.vterm.SendKey(vt.KeyPressEvent{Code: '/'})
	time.Sleep(100 * time.Millisecond)
	term.vterm.SendText("proto random")
	time.Sleep(50 * time.Millisecond)
	term.vterm.SendKey(vt.KeyPressEvent{Code: vt.KeyEnter})
	term.wait("position:")
	term.check("filter no matches")

	term.vterm.SendKey(vt.KeyPressEvent{Code: vt.KeyEscape})
	term.wait("position:")
	term.check("filter no matches clear")
}
