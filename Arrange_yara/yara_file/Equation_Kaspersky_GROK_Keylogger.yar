rule Equation_Kaspersky_GROK_Keylogger {
	meta:
		description = "Equation Group Malware - GROK keylogger"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "http://goo.gl/ivt8EW"
		date = "2015/02/16"
		hash = "50b8f125ed33233a545a1aac3c9d4bb6aa34b48f"
	strings:
		$s0 = "c:\\users\\rmgree5\\" ascii
		$s1 = "msrtdv.sys" fullword wide
		$x1 = "svrg.pdb" fullword ascii
		$x2 = "W32pServiceTable" fullword ascii
		$x3 = "In forma" fullword ascii
		$x4 = "ReleaseF" fullword ascii
		$x5 = "criptor" fullword ascii
		$x6 = "astMutex" fullword ascii
		$x7 = "ARASATAU" fullword ascii
		$x8 = "R0omp4ar" fullword ascii
		$z1 = "H.text" fullword ascii
		$z2 = "\\registry\\machine\\software\\Microsoft\\Windows NT\\CurrentVersion" fullword wide
		$z4 = "\\registry\\machine\\SYSTEM\\ControlSet001\\Control\\Session Manager\\Environment" wide fullword
	condition:
		uint16(0) == 0x5a4d and filesize < 250000 and
		(
			$s0 or
			( $s1 and 6 of ($x*) ) or
			( 6 of ($x*) and all of ($z*) )
		)
}