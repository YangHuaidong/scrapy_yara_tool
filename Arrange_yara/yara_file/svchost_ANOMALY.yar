rule svchost_ANOMALY {
	meta:
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		description = "Abnormal svchost.exe - typical strings not found in file"
		date = "23/04/2014"
		score = 55
	strings:
		$win2003_win7_u1 = "svchost.exe" wide nocase
		$win2003_win7_u3 = "coinitializesecurityparam" wide fullword nocase
		$win2003_win7_u4 = "servicedllunloadonstop" wide fullword nocase
		$win2000 = "Generic Host Process for Win32 Services" wide fullword
		$win2012 = "Host Process for Windows Services" wide fullword
	condition:
		filename == "svchost.exe"
      and uint16(0) == 0x5a4d
      and not 1 of ($win*) and not WINDOWS_UPDATE_BDC
}