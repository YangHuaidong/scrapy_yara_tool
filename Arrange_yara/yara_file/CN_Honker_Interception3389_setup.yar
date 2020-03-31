rule CN_Honker_Interception3389_setup {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file setup.exe"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "f5b2f86f8e7cdc00aa1cb1b04bc3d278eb17bf5c"
	strings:
		$s0 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify\\%s" fullword ascii /* PEStudio Blacklist: strings */
		$s1 = "%s\\temp\\temp%d.bat" fullword ascii /* PEStudio Blacklist: strings */
		$s5 = "EventStartShell" fullword ascii /* PEStudio Blacklist: strings */
		$s6 = "del /f /q \"%s\"" fullword ascii
		$s7 = "\\wminotify.dll" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 400KB and all of them
}