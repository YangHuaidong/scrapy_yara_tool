rule CN_Honker_GroupPolicyRemover {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file GroupPolicyRemover.exe"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "7475d694e189b35899a2baa462957ac3687513e5"
	strings:
		$s0 = "GP_killer.EXE" fullword wide /* PEStudio Blacklist: strings */
		$s1 = "GP_killer Microsoft " fullword wide /* PEStudio Blacklist: strings */
		$s2 = "SHDeleteKeyA" fullword ascii /* PEStudio Blacklist: strings */ /* Goodware String - occured 79 times */
	condition:
		uint16(0) == 0x5a4d and filesize < 700KB and all of them
}