rule CN_Honker_ms11080_withcmd {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file ms11080_withcmd.exe"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "745e5058acff27b09cfd6169caf6e45097881a49"
	strings:
		$s1 = "Usage : ms11-080.exe cmd.exe Command " fullword ascii /* PEStudio Blacklist: strings */
		$s3 = "[>] create pipe error" fullword ascii /* PEStudio Blacklist: strings */
	condition:
		uint16(0) == 0x5a4d and filesize < 340KB and all of them
}