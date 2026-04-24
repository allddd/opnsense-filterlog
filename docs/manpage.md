@PROGRAM@ 8 "April 24, 2026" "FreeBSD" "FreeBSD System Manager's Manual"
===

# NAME
@PROGRAM@ - command-line tool and terminal-based viewer for OPNsense firewall logs

# SYNOPSIS
**@PROGRAM@** [**-f** *expression*] [**-h**] [**-j**] [**-V**] [*file*]

# DESCRIPTION
**@PROGRAM@** is a command-line tool and terminal-based viewer for
analyzing OPNsense firewall logs. It can be used either as an interactive TUI
or to output log entries in JSON format for automation, etc. Both CLI and TUI
support filtering using a **tcpdump**(1)-like syntax with field- and time-based
filters, logical operators, and grouping.

# OPTIONS
The optional *file* argument specifies the path to the filter log file to
analyze. If omitted, defaults to */var/log/filter/latest.log*.

The options are as follows:

**-f** *expression*
:   Filter expression (requires **-j**).

**-h**
:   Display usage information and exit.

**-j**
:   Display entries as JSON and exit.

**-V**
:   Display version information and exit.

# COMMANDS
The following keys are available in the TUI:

| Key(s) | Action |
|--------|--------|
| `k` or `▲` | Scroll up |
| `j` or `▼` | Scroll down |
| `h` or `◄` | Scroll left |
| `l` or `►` | Scroll right |
| `u` or `PgUp` | Page up |
| `d` or `PgDn` | Page down |
| `g` or `Home` | Jump to top |
| `G` or `End` | Jump to bottom |
| `Enter` | View details |
| `/` | Enter filter mode |
| `q` | Quit |

# FILTER

## Simple search
Type a value without a field name to search across all fields:

```
192.168
block
tcp
```

## Field-based filtering
Use the *field* *value* syntax to target specific fields:

```
action block
dst 10.0.0.1
iface eth0
ip 4
label 02f4bab031b57d1e30553ce08e0ec131
port 443
proto tcp
src 192.168.1.1
```

Fields:

| Field | Alias(es) | Description |
|-------|-----------|-------------|
| `action` | - | Action (block, pass, etc.) |
| `destination` | `dst`, `dest` | Destination IP address |
| `direction` | `dir` | Direction (in or out) |
| `dstport` | `dport` | Destination port |
| `host` | - | Either source or destination IP address |
| `interface` | `iface` | Network interface |
| `ipversion` | `ip`, `ipver` | IP version (4 or 6) |
| `label` | - | Rule label |
| `port` | - | Either source or destination port |
| `protocol` | `proto` | Protocol (tcp, udp, icmp, etc.) |
| `reason` | - | Reason (match, fragment, etc.) |
| `source` | `src` | Source IP address |
| `srcport` | `sport` | Source port |

## Time-based filtering
Use `since` or `until` followed by a timestamp to filter entries by time:

```
since -30min
since -1h
since -2h and until -1h
since yesterday
until 14:00:00
since 14:00 and until 15:16:17
since 2009-11-10
since 2009-11-10T23:00:00Z
```

Timestamps are parsed using go-systemd-time, see
<https://pkg.go.dev/gitlab.com/allddd/go-systemd-time#ParseTimestamp> for all
supported timestamp formats. Note that the filter parser uses space as
delimiter, so only timestamps without spaces are supported (e.g. use
`2009-11-10T23:00:00` instead of `2009-11-10 23:00:00`).

## Logical operators
Combine filters with logical operators:

### AND (`and` or `&&`)
Both conditions must match:

```
src 192.168.1.1 and action block
proto tcp && port 443
```

### OR (`or` or `||`)
Either condition must match:

```
src 192.168.1.1 or src 192.168.1.2
port 80 || port 443
```

### NOT (`not` or `!`)
Inverts the condition:

```
not action block
! src 192.168.1.1
```

## Grouping
Use parentheses to group filters and control evaluation order:

```
(src 192.168.1.1 or src 192.168.1.2) and action block
proto tcp and (port 80 or port 443)
not (action pass and proto udp)
```

# EXAMPLES
View the default log file (*/var/log/filter/latest.log*):

```
@PROGRAM@
```

View a specific log file:

```
@PROGRAM@ /path/to/filter.log
```

Output blocked TCP traffic on port 443 as JSON:

```
@PROGRAM@ -j -f 'action block and proto tcp and port 443'
```

Output entries from the last hour as JSON:

```
@PROGRAM@ -j -f 'since -1h'
```

Output entries from a specific source IP in a specific log file as JSON:

```
@PROGRAM@ -j -f 'src 192.168.1.1' /path/to/filter.log
```

# EXIT STATUS
Exits 0 on success, and >0 if an error occurs.

# AUTHORS
allddd <me@allddd.onl>

Report bugs at: <@REPO@>
