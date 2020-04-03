rule EQGRP_noclient_3_0_5 {
	meta:
		description = "Detects tool from EQGRP toolset - file noclient-3.0.5.3"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Research"
		date = "2016-08-15"
		score = 75
	strings:
		$x1 = "-C %s 127.0.0.1\" scripme -F -t JACKPOPIN4 '&" fullword ascii
		$x2 = "Command too long!  What the HELL are you trying to do to me?!?!  Try one smaller than %d bozo." fullword ascii
		$x3 = "sh -c \"ping -c 2 %s; grep %s /proc/net/arp >/tmp/gx \"" fullword ascii
		$x4 = "Error from ourtn, did not find keys=target in tn.spayed" fullword ascii
		$x5 = "ourtn -d -D %s -W 127.0.0.1:%d  -i %s -p %d %s %s" fullword ascii
	condition:
		( uint16(0) == 0x457f and filesize < 700KB and 1 of them ) or ( all of them )
}