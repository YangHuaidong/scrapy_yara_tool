rule CN_Honker_Fpipe_FPipe {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file FPipe.exe"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 50
		hash = "a2c51c6fa93a3dfa14aaf31fb1c48a3a66a32d11"
	strings:
		$s1 = "Unable to create TCP listen socket. %s%d" fullword ascii /* PEStudio Blacklist: strings */
		$s2 = "http://www.foundstone.com" fullword ascii
		$s3 = "%s %s port %d. Address is already in use" fullword ascii /* PEStudio Blacklist: strings */
	condition:
		uint16(0) == 0x5a4d and filesize < 20KB and all of them
}