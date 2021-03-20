# 2ping - A bi-directional ping utility

![ci](https://github.com/rfinnie/2ping/workflows/ci/badge.svg)
![snapcraft](https://github.com/rfinnie/2ping/workflows/snapcraft/badge.svg)

https://www.finnie.org/software/2ping/

## About

2ping is a bi-directional ping utility.
It uses 3-way pings (akin to TCP SYN, SYN/ACK, ACK) and after-the-fact state comparison between a 2ping listener and a 2ping client to determine which direction packet loss occurs.

## Installation

2ping requires Python 3 version 3.6 or higher.

To install:

    sudo python3 setup.py install

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

Copyright (C) 2010-2020 [Ryan Finnie](https://www.finnie.org/)

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
02110-1301, USA.
