rule CN_Honker__lcx_HTran2_4_htran20 {
	meta:
		description = "Sample from CN Honker Pentest Toolset - from files lcx.exe, HTran2.4.exe, htran20.exe"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		super_rule = 1
		hash0 = "0c8779849d53d0772bbaa1cedeca150c543ebf38"
		hash1 = "524f986692f55620013ab5a06bf942382e64d38a"
		hash2 = "b992bf5b04d362ed3757e90e57bc5d6b2a04e65c"
	strings:
		$s1 = "[SERVER]connection to %s:%d error" fullword ascii /* PEStudio Blacklist: strings */
		$s2 = "[+] OK! I Closed The Two Socket." fullword ascii /* PEStudio Blacklist: strings */
		$s3 = "[+] Start Transmit (%s:%d <-> %s:%d) ......" fullword ascii /* PEStudio Blacklist: strings */
	condition:
		uint16(0) == 0x5a4d and filesize < 440KB and all of them
}