rule CN_Honker_WebRobot {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file WebRobot.exe"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "af054994c911b4301490344fca4bb19a9f394a8f"
	strings:
		$s1 = "%d-%02d-%02d %02d^%02d^%02d ScanReprot.htm" fullword ascii /* PEStudio Blacklist: strings */
		$s2 = "\\log\\ProgramDataFile.dat" fullword ascii /* PEStudio Blacklist: strings */
		$s3 = "\\data\\FilterKeyword.txt" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 2000KB and all of them
}