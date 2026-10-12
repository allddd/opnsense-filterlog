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
	"fmt"
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

var files = []string{
	"testdata/filter_20260726.log",
	"testdata/filter_20260727.log",
	"testdata/filter_20260728.log",
}

type terminal struct {
	t     *testing.T
	cmd   *exec.Cmd
	pty   xpty.Pty
	vterm *vt.SafeEmulator
}

func newTerminal(t *testing.T, width, height int, paths ...string) *terminal {
	t.Helper()
	pty, err := xpty.NewPty(width, height)
	if err != nil {
		t.Fatal(err)
	}
	vterm := vt.NewSafeEmulator(width, height)
	cmd := exec.CommandContext(t.Context(), "../../"+meta.Name, paths...)
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

func (term *terminal) check(name string) {
	term.t.Helper()
	term.t.Run(name, func(t *testing.T) {
		t.Helper()
		golden.RequireEqual(t, []byte(term.vterm.String()))
	})
}

func (term *terminal) filter(text string) {
	term.t.Helper()
	term.press('/')
	term.wait("enter: apply")
	term.vterm.SendText(text)
	term.wait("filter: " + text)
}

func (term *terminal) press(codes ...rune) {
	for _, code := range codes {
		term.vterm.SendKey(vt.KeyPressEvent{Code: code})
	}
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

func TestEmptyView(t *testing.T) {
	term := newTerminal(t, 80, 10, "/dev/null")
	term.wait("no valid entries")
	term.check("empty")
}

func TestNavigation(t *testing.T) {
	term := newTerminal(t, 100, 24, files...)
	term.wait("position:")
	term.check("default")

	term.press('j', vt.KeyDown, 'j')
	term.wait("position:")
	term.check("default scroll down")

	term.press('k', vt.KeyUp)
	term.wait("position:")
	term.check("default scroll up")

	term.press('d', vt.KeyPgDown)
	term.wait("position:")
	term.check("default page down")

	term.press('u', vt.KeyPgUp)
	term.wait("position:")
	term.check("default page up")

	term.press(vt.KeyEnd)
	term.wait("position:")
	term.check("default jump to end")

	term.press(vt.KeyHome)
	term.wait("position:")
	term.check("default jump to top")

	// get past reload threshold
	for range 40 {
		term.press(vt.KeyPgDown)
		time.Sleep(30 * time.Millisecond)
	}
	term.wait("position:")
	term.check("default page down past loaded block")

	term.press(vt.KeyEnter)
	term.wait("esc: back")
	term.check("details after page down past loaded block")

	term.press(vt.KeyEscape)
	term.wait("position:")
	for range 40 {
		term.press(vt.KeyPgUp)
		time.Sleep(30 * time.Millisecond)
	}
	term.wait("position:")
	term.check("default page up past loaded block")

	term.press(vt.KeyRight, 'l')
	term.wait("position:")
	term.check("default horizontal scroll right")

	term.press(vt.KeyEnter, vt.KeyEscape)
	term.wait("position:")
	term.check("details back after horizontal scroll")

	term.press('e', vt.KeyEscape)
	term.wait("position:")
	term.check("errors back after horizontal scroll")

	term.press('h', vt.KeyLeft)
	term.wait("position:")
	term.check("default horizontal scroll left")

	term.press(vt.KeyEnter)
	term.wait("esc: back")
	term.check("details")

	term.press('j', vt.KeyDown)
	term.wait("esc: back")
	term.check("details scroll down")

	term.press('G')
	term.wait("esc: back")
	term.check("details jump to end")

	term.press(vt.KeyEscape)
	term.wait("position:")
	term.check("details back")

	term.press('e')
	term.wait("esc: back")
	term.check("errors")

	term.press('j', vt.KeyDown)
	term.wait("esc: back")
	term.check("errors scroll down")

	term.press('l')
	term.wait("esc: back")
	term.check("errors horizontal scroll right")

	term.press('h')
	term.wait("esc: back")
	term.check("errors horizontal scroll left")

	term.press('G')
	term.wait("esc: back")
	term.check("errors jump to end")

	term.press(vt.KeyEscape)
	term.wait("position:")
	term.check("errors back")
}

func TestDetailsView(t *testing.T) {
	tests := []struct {
		name   string
		filter string
	}{
		{"gre4", "proto gre"},
		{"icmp4", "proto icmp"},
		{"ipencap4", "proto ipencap"},
		{"ipv6 encapsulation", "proto ipv6"},
		{"sctp4", "proto sctp"},
		{"tcp4", "ipver 4 and proto tcp"},
		{"tcp4 with error message", "src 10.161.149.187"},
		{"udp4", "ipver 4 and proto udp"},
		{"icmp6", "proto ipv6-icmp"},
		{"tcp6", "ipver 6 and proto tcp"},
		{"udp6", "ipver 6 and proto udp"},
	}
	term := newTerminal(t, 100, 24, files...)
	term.wait("position:")
	for _, tc := range tests {
		term.filter(tc.filter)
		term.press(vt.KeyEnter)
		term.wait(fmt.Sprintf("filter: %q", tc.filter))
		term.press(vt.KeyEnter)
		term.wait("esc: back")
		term.check(tc.name)

		term.press(vt.KeyEscape)
		term.wait("esc: clear")
		term.press(vt.KeyEscape)
		term.wait("position:")
	}
}

func TestFilterView(t *testing.T) {
	term := newTerminal(t, 100, 24, files...)
	term.wait("position:")

	term.filter("invalid")
	term.press(vt.KeyEscape)
	term.wait("position:")
	term.check("filter cancel")

	term.filter("q")
	term.check("filter typing q")

	term.press(vt.KeyEscape)
	term.wait("position:")
	term.press('/', ' ', ' ', ' ', vt.KeyEnter)
	term.wait("empty filter expression")
	term.check("filter whitespace")

	term.press(vt.KeyEscape)
	term.wait("position:")
	term.filter("proto and")
	term.press(vt.KeyEnter)
	term.wait("position:")
	term.check("filter invalid")

	term.press(vt.KeyEscape)
	term.wait("position:")
	term.filter("proto random")
	term.press(vt.KeyEnter)
	term.wait(`filter: "proto random"`)
	term.check("filter no matches")

	term.press(vt.KeyEscape)
	term.wait("position:")
	term.check("filter no matches clear")

	term.filter("proto gre")
	term.press(vt.KeyEnter)
	term.wait(`filter: "proto gre"`)
	term.check("filter apply")

	term.press('/', vt.KeyEscape)
	term.wait(`filter: "proto gre"`)
	term.check("filter apply cancel")

	term.press(vt.KeyEnter)
	term.wait("esc: back")
	term.check("filter details")

	term.press(vt.KeyEscape)
	term.wait("position:")
	term.check("filter details back")

	term.press(vt.KeyEscape)
	term.wait("position:")
	term.check("filter clear")

	term.filter("proto udp")
	term.press(vt.KeyEnter)
	term.wait(`filter: "proto udp"`)
	term.check("filter large")

	term.press(vt.KeyEnd)
	term.wait("position:")
	term.check("filter large jump to end")

	term.press(vt.KeyHome)
	term.wait("position:")
	term.check("filter large jump to top")

	// get past reload threshold
	for range 40 {
		term.press(vt.KeyPgDown)
		time.Sleep(30 * time.Millisecond)
	}
	term.wait("position:")
	term.check("filter large page down past loaded block")

	term.press(vt.KeyEnter)
	term.wait("esc: back")
	term.check("filter large details after page down past loaded block")

	term.press(vt.KeyEscape)
	term.wait("position:")
	term.press(vt.KeyEscape)
	term.wait("position:")
	term.filter("since 2026-07-26T23:59:40Z and until 2026-07-27T00:00:09Z")
	term.press(vt.KeyEnter)
	term.wait(`filter: "since`)
	term.check("filter across files")
}

func TestQuit(t *testing.T) {
	tests := []struct {
		name string
		keys []vt.KeyPressEvent
	}{
		{"q", []vt.KeyPressEvent{{Code: 'q'}}},
		{"q in details view", []vt.KeyPressEvent{{Code: vt.KeyEnter}, {Code: 'q'}}},
		{"q in errors view", []vt.KeyPressEvent{{Code: 'e'}, {Code: 'q'}}},
		{"ctrl+c", []vt.KeyPressEvent{{Code: 'c', Mod: vt.ModCtrl}}},
		{"ctrl+c while typing filter", []vt.KeyPressEvent{{Code: '/'}, {Code: 'c', Mod: vt.ModCtrl}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			term := newTerminal(t, 100, 24, files[0])
			term.wait("position:")
			for _, key := range tc.keys {
				term.vterm.SendKey(key)
			}
			if err := term.cmd.Wait(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
