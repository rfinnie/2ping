% 2PING(1) | 2ping
% Ryan Finnie
# NAME

2ping - A bi-directional ping utility

# SYNOPSIS

2ping [*options*] *--listen* | host/IP

# DESCRIPTION

`2ping` is a bi-directional ping utility.
It uses 3-way pings (akin to TCP SYN, SYN/ACK, ACK) and after-the-fact state comparison between a 2ping listener and a 2ping client to determine which direction packet loss occurs.

To use 2ping, start a listener on a known stable network host.
The relative network stability of the 2ping listener host should not be in question, because while 2ping can determine whether packet loss is occurring inbound or outbound relative to an endpoint, that will not help you determine the cause if both of the endpoints are in question.

Once the listener is started, start 2ping in client mode and tell it to connect to the listener.
The ends will begin pinging each other and displaying network statistics.
If packet loss occurs, 2ping will wait a few seconds (default 10, configurable with -w) before comparing notes between the two endpoints to determine which direction the packet loss is occurring.

To quit 2ping on the client or listener ends, enter \^C, and a list of statistics will be displayed.
To get a short inline display of statistics without quitting, send the process a QUIT signal (yes, that's the opposite of what you would think, but it's in line with the normal ping utility).

# OPTIONS

`ping`-compatible options (long option names are `2ping`-specific):

--audible, -a
:   Audible ping.

--adaptive, -A
:   Adaptive ping.
    A new client ping request is sent as soon as a client ping response is received.
    If a ping response is not received within the interval period, a new ping request is sent.
    On networks with low rtt this mode is essentially equivalent to flood mode.

--count=*count*, -c *count*
:   Stop after sending *count* ping requests.

    `2ping`-specific notes: This option behaves slightly differently from `ping`.
    If both *-c* and *-w* are specified, satisfaction of *-c* will cause an exit first.
    Also, internally, `2ping` exits just before sending *count*+1 pings, to give time for the ping to complete.

--flood, -f
:   Flood ping.
    For every ping sent a period "." is printed, while for ever ping received a backspace is printed.
    This provides a rapid display of how many pings are being dropped.
    If interval is not given, it sets interval to zero and outputs pings as fast as they come back or one hundred times per second, whichever is more.

    `2ping`-specific notes: Detected outbound/inbound loss responses are printed as "\>" and "\<", respectively.
    Receive errors are printed as "E".
    Due to the asynchronous nature of `2ping`, successful responses (backspaces) may overwrite these loss and error characters.

--interval=*interval*, -i *interval*
:   Wait *interval* seconds between sending each ping.
    The default is to wait for one second between each ping normally, or not to wait in flood mode.

--interface-address=*address*, -I *address*
:   Set source IP address.
    When in listener mode, this option may be specified multiple to bind to multiple IP addresses.
    When in client mode, this option may only be specified once, and all outbound pings will be bound to this source IP.

    `2ping`-specific notes: This option only takes an IP address, not a device name.
    Note that in listener mode, if the machine has an interface with multiple IP addresses and an request comes in via a sub IP, the reply still leaves via the interface's main IP.
    So this option must be used if you would like to respond via an interface's sub-IP.

--preload=*count*, -l *count*
:   If specified, `2ping` sends that many packets not waiting for reply.

--pattern=*hex_bytes*, -p *hex_bytes*
:   You may specify up to 16 "pad" bytes to fill out the packets you send.
    This is useful for diagnosing data-dependent problems in a network.
    For example, *-p ff* will cause the sent packet pad area to be filled with all ones.

    `2ping`-specific notes: This pads the portion of the packet that does not contain the active payload data.
    If the active payload data is larger than the minimum packet size (*--min-packet-size*), no padding will be sent.

--quiet, -q
:   Quiet output.
    Nothing is displayed except the summary lines at startup time and when finished.

--packetsize-compat=*bytes*, -s *bytes*
:   `ping` compatibility, this will set *--min-packet-size* to this plus 8 bytes.

--verbose, -v
:   Verbose output.
    In `2ping`, this prints decodes of packets that are sent and received.

--version, -V
:   Show version and exit.

--deadline=*seconds*, -w *seconds*
:   Specify a timeout, in seconds, before `2ping` exits regardless of how many pings have been sent or received.
    Due to blocking, this may occur up to one second after the deadline specified.

    `2ping`-specific notes: This option behaves slightly differently from `ping`.
    If both *-c* and *-w* are specified, satisfaction of *-c* will cause an exit first.

`2ping`-specific options:

-h, --help
:   Print a synposis and exit.

-4, --ipv4
:   Limit binds to IPv4.

-6, --ipv6
:   Limit binds to IPv6.

--auth=*key*
:   Set a shared key, send cryptographic hashes with each packet, and require cryptographic hashes from peer packets signed with the same shared key.

--auth-digest=*digest*
:   When *--auth* is used, specify the digest type to compute the cryptographic hash.
    Valid options are `hmac-md5` (default), `hmac-sha1` and `hmac-sha256`.

--debug
:   Print (lots of) debugging information.

--inquire-wait=*secs*
:   Wait at least *secs* seconds before inquiring about a lost packet.
    Default is 10 seconds.
    UDP packets can arrive delayed or out of order, so it is best to give it some time before inquiring about a lost packet.

--listen
:   Start as a listener.
    The listener will not send out ping requests at regular intervals, and will instead wait for the far end to initiate ping requests.
    A listener is required as the remote end for a client.

--min-packet-size=*min*
:   Set the minimum total payload size to *min* bytes, default 128.
    If the payload is smaller than *min* bytes, padding will be added to the end of the packet.

--max-packet-size=*max*
:   Set the maximum total payload size to *max* bytes, default 512, absolute minimum 64.
    If the payload is larger than *max* bytes, information will be rearranged and sent in future packets when possible.

--no-3way
:   Do not perform 3-way pings.
    Used most often when combined with *--listen*, as the listener is usually the one to determine whether a ping reply should become a 3-way ping.

    Strictly speaking, a 3-way ping is not necessary for determining directional packet loss between the client and the listener.
    However, the extra leg of the 3-way ping allows for extra chances to determine packet loss more efficiently.
    Also, with 3-way ping disabled, the listener will receive no client performance indicators, nor will the listener be able to determine directional packet loss that it detects.

--no-match-packet-size
:   When sending replies, 2ping will try to match the packet size of the received packet by adding padding if necessary, but will not exceed *--max-packet-size*.
    *--no-match-packet-size* disabled this behavior, always setting the minimum to *--min-packet-size*.

--no-send-version
:   Do not send the current running version of 2ping with each packet.

--notice=*text*
:   Arbitrary notice text to send with each packet.
    If the remote peer supports it, this may be displayed to the user.

--packet-loss=*out:in*
:   Simulate random packet loss outbound and inbound.
    For example, *25:10* means a 25% chance of not sending a packet, and a 10% chance of ignoring a received packet.
    A single number without colon separation means use the same percentage for both outbound and inbound.

--port=*port*
:   Use UDP port *port*.
    With *--listen*, this is the port to bind as, otherwise this is the port to send to.
    Default is UDP port 15998.

--stats=*interval*
:   Print a line of brief current statistics every *interval* seconds.
    The same line can be printed on demand by sending SIGQUIT to the 2ping process.

# BUGS

None known, many assumed.

# AUTHOR

`2ping` was written by Ryan Finnie \<ryan@finnie.org\>.
