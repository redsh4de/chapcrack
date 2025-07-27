chapcrack
=================

A tool for parsing and decrypting MS-CHAPv2 network handshakes. Upgraded version with Python 3, John The Ripper support.

1. 	The first thing you'll need to do is obtain the network traffic 
	for the MS-CHAPv2 handshake you'd like to crack.  

	For PPTP VPN connections, simply use a tool such as tcpdump or 
	wireshark in order to obtain a network capture. 
	For WPA2 Enterprise wireless handshakes, simply use a tool like 
	FreeRADIUS-WPE in order to obtain 'challenge' and 'response' 
	parameters.

2. 	Next you'll use `chapcrack` in order to parse and extract the 
	MS-CHAPv2 handshake from your packet capture or FreeRADIUS 
	interception.

	1.	For a PPTP handshake, run: `chapcrack.py parse -i /path/to/capture.pcap`
	2.	For a WPA2 handshake, run `chapcrack.py radius -C <challenge> -R <response>`, where `challenge` and `response` are what you intercepted with
		FreeRADIUS-WPE

3.	Crack the John the Ripper hash you received to get the plaintext password.

4.	When you get your results, you can decrypt a PPTP packet capture:
	`chapcrack.py decrypt -i </path/to/capture.cap> -o output.cap -p <password>`

Bug tracker
-----------

Have a bug? Please create an issue here on GitHub!

https://github.com/redsh4de/chapcrack/issues

Copyright
---------

Copyright 2012 Moxie Marlinspike

Licensed under the GPLv3: http://www.gnu.org/licenses/gpl-3.0.html
