rule CN_Honker_ShiftBackdoor_Server {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file Server.dat"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "b24d761c6bbf216792c4833890460e8b37d86b37"
	strings:
		$s0 = "del /q /f %systemroot%system32sethc.exe" fullword ascii /* PEStudio Blacklist: strings */
		$s1 = "cacls %s /t /c /e /r administrators" fullword ascii /* PEStudio Blacklist: strings */
		$s2 = "\\dllcache\\sethc.exe" fullword ascii
		$s3 = "\\ntvdm.exe" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 200KB and 2 of them
}