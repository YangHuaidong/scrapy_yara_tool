rule APT28_CHOPSTICK {
	meta:
		description = "Detects a malware that behaves like CHOPSTICK mentioned in APT28 report"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://goo.gl/v3ebal"
		date = "2015-06-02"
		hash = "f4db2e0881f83f6a2387ecf446fcb4a4c9f99808"
		score = 60
	strings:
		$s0 = "jhuhugit.tmp" fullword ascii /* score: '14.005' */
		$s8 = "KERNEL32.dll" fullword ascii /* PEStudio Blacklist: strings */ /* score: '5' */ /* Goodware String - occured 14405 times */
		$s9 = "IsDebuggerPresent" fullword ascii /* PEStudio Blacklist: strings */ /* score: '5' */ /* Goodware String - occured 3518 times */
		$s10 = "IsProcessorFeaturePresent" fullword ascii /* PEStudio Blacklist: strings */ /* score: '5' */ /* Goodware String - occured 1383 times */
		$s11 = "TerminateProcess" fullword ascii /* PEStudio Blacklist: strings */ /* score: '5' */ /* Goodware String - occured 13081 times */
		$s13 = "DeleteFileA" fullword ascii /* PEStudio Blacklist: strings */ /* score: '5' */ /* Goodware String - occured 1384 times */
		$s15 = "GetProcessHeap" fullword ascii /* PEStudio Blacklist: strings */ /* score: '5' */ /* Goodware String - occured 5875 times */
		$s16 = "!This program cannot be run in DOS mode." fullword ascii /* PEStudio Blacklist: strings */ /* score: '5' */ /* Goodware String - occured 20908 times */
		$s17 = "LoadLibraryA" fullword ascii /* PEStudio Blacklist: strings */ /* score: '5' */ /* Goodware String - occured 5461 times */
	condition:
		uint16(0) == 0x5a4d and filesize < 722KB and all of them
}