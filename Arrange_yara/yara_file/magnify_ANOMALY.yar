rule magnify_ANOMALY {
	meta:
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		description = "Abnormal magnify.exe (Magnifier) - typical strings not found in file"
		date = "01/06/2014"
		score = 55
	strings:
		$win7 = "Microsoft Screen Magnifier" wide fullword
		$win2000 = "Microsoft Magnifier" wide fullword
		$winxp = "Software\\Microsoft\\Magnify" wide
	condition:
		filename =="magnify.exe"
      and uint16(0) == 0x5a4d
      and not 1 of ($win*) and not WINDOWS_UPDATE_BDC
}