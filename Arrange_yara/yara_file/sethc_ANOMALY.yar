rule sethc_ANOMALY {
	meta:
		description = "Sethc.exe has been replaced - Indicates Remote Access Hack RDP"
		author = "F. Roth"
		reference = "http://www.emc.com/collateral/white-papers/h12756-wp-shell-crew.pdf"
		date = "2014/01/23"
		score = 70
	strings:
		$s1 = "stickykeys" fullword nocase
		$s2 = "stickykeys" wide nocase
		$s3 = "Control_RunDLL access.cpl" wide fullword
		$s4 = "SETHC.EXE" wide fullword
	condition:
		filename == "sethc.exe"
      and uint16(0) == 0x5a4d
      and not 1 of ($s*) and not WINDOWS_UPDATE_BDC
}