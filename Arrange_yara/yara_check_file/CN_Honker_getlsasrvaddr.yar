rule CN_Honker_getlsasrvaddr {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file getlsasrvaddr.exe - WCE Amplia Security"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "a897d5da98dae8d80f3c0a0ef6a07c4b42fb89ce"
	strings:
		$s8 = "pingme.txt" fullword ascii /* PEStudio Blacklist: strings */
		$s16 = ".\\lsasrv.pdb" fullword ascii
		$s20 = "Addresses Found: " fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 100KB and all of them
}