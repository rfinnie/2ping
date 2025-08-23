# 2ping - A bi-directional ping utility

![ci](https://github.com/rfinnie/2ping/workflows/ci/badge.svg)

https://www.finnie.org/software/2ping/

## About

2ping is a bi-directional ping utility.
It uses 3-way pings (akin to TCP SYN, SYN/ACK, ACK) and after-the-fact state comparison between a 2ping listener and a 2ping client to determine which direction packet loss occurs.

## Installation

2ping requires Python 3 version 3.6 or higher.

To install 2ping with all optional dependencies as a pipx package:

    pipx install '.[full]'

Python 3 stdlib is the only requirement for base functionality, but 2ping can utilize the following modules if available:

* [distro](https://pypi.org/project/distro/) for system distribution detection
* [dnspython](https://pypi.org/project/dnspython/) for --srv
* [netifaces](https://pypi.org/project/netifaces/) for listening on all addresses in --listen mode
* [pycryptodomex](https://pypi.org/project/pycryptodomex/) (recommended) or [pycryptodome](https://pypi.org/project/pycryptodome/) or [pycrypto](https://pypi.org/project/pycrypto/) for --encrypt
* [systemd](https://pypi.org/project/systemd/) for using systemd-supplied sockets

## Usage

Please see the 2ping manpage for invocation options, but in short, start a listener on the far end:

    2ping --listen

And run 2ping on the near end, connecting to the far end listener:

    2ping $LISTENER

Where "$LISTENER" is the name or IP address of the listener.

## License

2ping - A bi-directional ping utility

Copyright (C) 2010-2025 [Ryan Finnie](https://www.finnie.org/)

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this
file, You can obtain one at http://mozilla.org/MPL/2.0/.

This document is provided under the following license:

    SPDX-PackageSummary: 2ping - A bi-directional ping utility
    SPDX-FileCopyrightText: Copyright (C) 2010-2025 Ryan Finnie
    SPDX-License-Identifier: CC-BY-SA-4.0
