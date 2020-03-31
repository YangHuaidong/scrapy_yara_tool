rule CN_Honker_HTran2_4 {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file HTran2.4.exe"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "524f986692f55620013ab5a06bf942382e64d38a"
	strings:
		$s1 = "Enter Your Socks Type No: [0.BindPort 1.ConnectBack 2.Listen]:" fullword ascii /* PEStudio Blacklist: strings */
		$s2 = "[+] New connection %s:%d !!" fullword ascii /* PEStudio Blacklist: strings */
	condition:
		uint16(0) == 0x5a4d and filesize < 180KB and all of them
}