rule CN_Honker_lcx_lcx {
	meta:
		description = "Sample from CN Honker Pentest Toolset - HTRAN - file lcx.exe"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "0c8779849d53d0772bbaa1cedeca150c543ebf38"
	strings:
		$s1 = "%s -<listen|tran|slave> <option> [-log logfile]" fullword ascii /* PEStudio Blacklist: strings */
		$s2 = "=========== Code by lion & bkbll" ascii
		$s3 = "Welcome to [url]http://www.cnhonker.com[/url] " ascii
		$s4 = "-tran   <ConnectPort> <TransmitHost> <TransmitPort>" fullword ascii /* PEStudio Blacklist: strings */
		$s5 = "[+] Start Transmit (%s:%d <-> %s:%d) ......" fullword ascii /* PEStudio Blacklist: strings */
	condition:
		uint16(0) == 0x5a4d and filesize < 30KB and 1 of them
}