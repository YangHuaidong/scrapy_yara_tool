rule CN_Honker_GetHashes_2 {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file GetHashes.exe"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "35ae9ccba8d607d8c19a065cf553070c54b091d8"
	strings:
		$s1 = "GetHashes.exe <SAM registry file> [System key file]" fullword ascii /* PEStudio Blacklist: strings */
		$s2 = "GetHashes.exe $Local" fullword ascii
		$s3 = "The system key doesn't match SAM registry file!" fullword ascii /* PEStudio Blacklist: strings */
	condition:
		uint16(0) == 0x5a4d and filesize < 300KB and 2 of them
}