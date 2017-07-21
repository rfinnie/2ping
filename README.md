# 2ping - A bi-directional ping utility

https://www.finnie.org/software/2ping/

## About

2ping is a bi-directional ping utility.
It uses 3-way pings (akin to TCP SYN, SYN/ACK, ACK) and after-the-fact state comparison between a 2ping listener and a 2ping client to determine which direction packet loss occurs.

## Installation

Python 3 version 3.4 (XXX verify) or higher is required for 2ping.

To install:

    sudo python3 setup.py install

## Usage

Please see the 2ping manpage for invocation options, but in short, start a listener on the far end:

    2ping --listen

And run 2ping on the near end, connecting to the far end listener:

    2ping $LISTENER

Where "$LISTENER" is the name or IP address of the listener.

## License

2ping - A bi-directional ping utility

Copyright (C) 2010-2017 [Ryan Finnie](https://www.finnie.org/)

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
