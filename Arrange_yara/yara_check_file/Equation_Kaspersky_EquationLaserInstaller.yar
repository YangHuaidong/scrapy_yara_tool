rule Equation_Kaspersky_EquationLaserInstaller {
	meta:
		description = "Equation Group Malware - EquationLaser Installer"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "http://goo.gl/ivt8EW"
		date = "2015/02/16"
		hash = "5e1f56c1e57fbff96d4999db1fd6dd0f7d8221df"
	strings:
		$s0 = "Failed to get Windows version" fullword ascii
		$s1 = "lsasrv32.dll and lsass.exe" fullword wide
		$s2 = "\\\\%s\\mailslot\\%s" fullword ascii
		$s3 = "%d-%d-%d %d:%d:%d Z" fullword ascii
		$s4 = "lsasrv32.dll" fullword ascii
		$s5 = "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" fullword ascii
		$s6 = "%s %02x %s" fullword ascii
		$s7 = "VIEWERS" fullword ascii
		$s8 = "5.2.3790.220 (srv03_gdr.040918-1552)" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 250000 and 6 of ($s*)
}