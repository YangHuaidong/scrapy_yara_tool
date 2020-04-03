rule PoisonIvy_Sample_APT_3 {
	meta:
		description = "Detects a PoisonIvy Malware"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		score = 70
		reference = "VT Analysis"
		date = "2015-06-03"
		hash = "df3e1668ac20edecc12f2c1a873667ea1a6c3d6a"
	strings:
		$s0 = "\\notepad.exe" fullword ascii /* score: '11.025' */
		$s1 = "\\RasAuto.dll" fullword ascii /* score: '11.025' */
		$s3 = "winlogon.exe" fullword ascii /* PEStudio Blacklist: strings */ /* score: '5' */ /* Goodware String - occured 13 times */
	condition:
		uint16(0) == 0x5a4d and all of them
}