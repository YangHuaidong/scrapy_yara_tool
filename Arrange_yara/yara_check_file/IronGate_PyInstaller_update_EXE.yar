rule IronGate_PyInstaller_update_EXE {
	meta:
		description = "Detects a PyInstaller file named update.exe as mentioned in the IronGate APT"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://goo.gl/Mr6M2J"
		date = "2016-06-04"
		score = 60
		hash1 = "2044712ceb99972d025716f0f16aa039550e22a63000d2885f7b7cd50f6834e0"
	strings:
		$s1 = "bpython27.dll" fullword ascii
		$s5 = "%s%s.exe" fullword ascii
		$s6 = "bupdate.exe.manifest" fullword ascii
		$s9 = "bunicodedata.pyd" fullword ascii
		$s11 = "distutils.sysconfig(" fullword ascii
		$s16 = "distutils.debug(" fullword ascii
		$s18 = "supdate" fullword ascii
	condition:
		uint16(0) == 0x5a4d and all of them
}