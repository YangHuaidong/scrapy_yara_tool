rule Equation_Kaspersky_SuspiciousString {
	meta:
		description = "Equation Group Malware - suspicious string found in sample"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "http://goo.gl/ivt8EW"
		date = "2015/02/17"
		score = 60
	strings:
		$s1 = "i386\\DesertWinterDriver.pdb" fullword
		$s2 = "Performing UR-specific post-install..."
		$s3 = "Timeout waiting for the \"canInstallNow\" event from the implant-specific EXE!"
		$s4 = "STRAITSHOOTER30.exe"
		$s5 = "standalonegrok_2.1.1.1"
		$s6 = "c:\\users\\rmgree5\\"
	condition:
		uint16(0) == 0x5a4d and filesize < 500000 and all of ($s*)
}