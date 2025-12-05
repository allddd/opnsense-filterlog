# opnsense-filterlog

- [Overview](#overview)
- [Installation](#installation)
  - [Binary](#binary)
  - [Source](#source)
- [Usage](#usage)
  - [CLI](#cli)
  - [TUI](#tui)
  - [Filter](#filter)
- [Contributing](#contributing)
  - [Questions](#questions)
  - [Feedback](#feedback)
  - [Code](#code)
- [Copyright](#copyright)

## Overview

`opnsense-filterlog` is a terminal-based viewer for [OPNsense](https://opnsense.org) firewall logs. It works similarly to a pager like `less`, but with filtering/searching capabilities built specifically for firewall logs.

Features:
- Fast and resource-efficient, can process large log files even on low-spec devices.
- Filter syntax (similar to `tcpdump`) with field-based filters, logical operators and grouping.
- Self-contained binary with no external dependencies.
- TUI with `vi`/`less`-style keybindings.

![TUI Screenshot](./docs/demo.png)

## Installation

### Binary

You can download the pre-built binary along with its PGP-signed SHA256 checksum ([PGP key](https://gitlab.com/allddd.gpg)) from the [releases page](https://gitlab.com/allddd/opnsense-filterlog/-/releases/permalink/latest). All releases are reproducible, meaning you can compile the binary yourself and verify it matches the official release.

### Source

Clone the repository (replace `<version>` with the actual version, e.g. `v0.3.0`):

```sh
git clone https://gitlab.com/allddd/opnsense-filterlog.git -b <version>
```

Build the binary:

```sh
cd ./opnsense-filterlog
make build-release
```

## Usage

### CLI

You can view the default log file (`/var/log/filter/latest.log`) using:

```sh
opnsense-filterlog
```

Alternatively, view a specific log file using:

```sh
opnsense-filterlog /path/to/filter.log
```

To see all options, display help using:

```sh
opnsense-filterlog -h
```

### TUI

You can interact with the TUI using:

- **`k`** or **`▲`** / **`g`** or **`Home`** - Scroll/jump up
- **`j`** or **`▼`** / **`G`** or **`End`** - Scroll/jump down
- **`h`** or **`◄`** / **`0`** - Scroll/jump left
- **`l`** or **`►`** / **`$`** - Scroll/jump right
- **`u`** or **`PgUp`** - Page up
- **`d`** or **`PgDn`** - Page down
- **`/`** - Enter filter mode
- **`q`** - Quit

### Filter

#### Simple search

Type a value without a field name to search across all fields:

```
192.168
block
tcp
```

#### Field-based filtering

Use the `field value` syntax to target specific fields:

```
src 192.168.1.1
dst 10.0.0.1
action block
proto tcp
ip 4
port 443
iface eth0
```

Fields:

| Field | Aliases | Description |
|-------|---------|-------------|
| `action` | - | Action (block, pass, etc.) |
| `direction` | `dir` | Direction (in, out, etc.) |
| `destination` | `dst`, `dest` | Destination IP address |
| `interface` | `iface` | Network interface |
| `ipversion` | `ip`, `ipver` | IP version (4 or 6) |
| `port` | - | Either source or destination port |
| `srcport` | `sport` | Source port |
| `dstport` | `dport` | Destination port |
| `protocol` | `proto` | Protocol (tcp, udp, icmp, etc.) |
| `reason` | - | Reason (match, fragment, etc.) |
| `source` | `src` | Source IP address |

#### Logical operators

Combine filters with logical operators:

**AND** (`and` or `&&`) - Both conditions must match:

```
src 192.168.1.1 and action block
proto tcp && port 443
```

**OR** (`or` or `||`) - Either condition must match:

```
src 192.168.1.1 or src 192.168.1.2
port 80 || port 443
```

**NOT** (`not` or `!`) - Inverts the condition:

```
not action block
! src 192.168.1.1
```

#### Grouping

Use parentheses to group filters and control evaluation order:

```
(src 192.168.1.1 or src 192.168.1.2) and action block
proto tcp and (port 80 or port 443)
not (action pass and proto udp)
```

## Contributing

### Questions

Before asking a question, please read the [documentation](https://gitlab.com/allddd/opnsense-filterlog#opnsense-filterlog) and search for [existing issues](https://gitlab.com/allddd/opnsense-filterlog/-/issues). If those don't answer your question, [open an issue](https://gitlab.com/allddd/opnsense-filterlog/-/issues/new).

### Feedback

Before reporting a bug or requesting a feature, make sure you're using the [latest version](https://gitlab.com/allddd/opnsense-filterlog/-/releases/permalink/latest) and have searched [existing issues](https://gitlab.com/allddd/opnsense-filterlog/-/issues). After confirming it hasn't been reported/requested, [open an issue](https://gitlab.com/allddd/opnsense-filterlog/-/issues/new) that includes as much detail as possible (for bugs: expected versus actual behavior, steps to reproduce, environment details, error messages, anonymized log files; for features: description, use cases, etc.).

### Code

Before opening a merge request, please [open an issue](https://gitlab.com/allddd/opnsense-filterlog/-/issues/new) to discuss the change you want to make and search [existing issues](https://gitlab.com/allddd/opnsense-filterlog/-/issues) first to avoid duplicates. Before submitting a merge request, make sure `make test` passes, your code follows go conventions (`make fmt` and `make modernize`), new features have tests, and documentation is updated.

Commit messages must follow the [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) specification (see `git log` for examples):

## Copyright

This project is licensed under the BSD 2-Clause License. See [LICENSE](./LICENSE) for more details.
