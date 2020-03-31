rule Equation_Kaspersky_EquationDrugInstaller {
	meta:
		description = "Equation Group Malware - EquationDrug installer LUTEUSOBSTOS"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "http://goo.gl/ivt8EW"
		date = "2015/02/16"
		hash = "61fab1b8451275c7fd580895d9c68e152ff46417"
	strings:
		$s0 = "\\system32\\win32k.sys" fullword wide
		$s1 = "ALL_FIREWALLS" fullword ascii
		$x1 = "@prkMtx" fullword wide
		$x2 = "STATIC" fullword wide
		$x3 = "windir" fullword wide
		$x4 = "cnFormVoidFBC" fullword wide
		$x5 = "CcnFormSyncExFBC" fullword wide
		$x6 = "WinStaObj" fullword wide
		$x7 = "BINRES" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 500000 and all of ($s*) and 5 of ($x*)
}