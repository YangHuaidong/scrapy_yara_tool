rule CN_Honker_exp_ms11011 {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file ms11011.exe"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "5ad7a4962acbb6b0e3b73d77385eb91feb88b386"
	strings:
		$s0 = "\\i386\\Hello.pdb" ascii /* PEStudio Blacklist: strings */
		$s1 = "OS not supported." fullword ascii /* PEStudio Blacklist: strings */
		$s2 = ".Rich5" fullword ascii
		$s3 = "Not supported." fullword wide /* PEStudio Blacklist: strings */ /* Goodware String - occured 3 times */
		$s5 = "cmd.exe" fullword ascii /* PEStudio Blacklist: strings */ /* Goodware String - occured 120 times */
	condition:
		uint16(0) == 0x5a4d and filesize < 100KB and all of them
}