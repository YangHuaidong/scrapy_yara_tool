rule CN_Honker_DLL_passive_privilege_escalation_ws2help {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file ws2help.dll"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "e539b799c18d519efae6343cff362dcfd8f57f69"
	strings:
		$s0 = "PassMinDll.dll" fullword ascii
		$s1 = "\\ws2help.dll" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 30KB and all of them
}