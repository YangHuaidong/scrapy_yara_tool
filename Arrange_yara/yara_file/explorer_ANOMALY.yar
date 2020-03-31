rule explorer_ANOMALY {
	meta:
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		description = "Abnormal explorer.exe - typical strings not found in file"
		date = "27/05/2014"
		score = 55
	strings:
		$s1 = "EXPLORER.EXE" wide fullword
		$s2 = "Windows Explorer" wide fullword
	condition:
		filename == "explorer.exe"
      and uint16(0) == 0x5a4d
      and not filepath contains "teamviewer"
      and not 1 of ($s*) and not WINDOWS_UPDATE_BDC
}