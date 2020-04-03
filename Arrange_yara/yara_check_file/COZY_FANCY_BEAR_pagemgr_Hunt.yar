rule COZY_FANCY_BEAR_pagemgr_Hunt {
	meta:
		description = "Detects a pagemgr.exe as mentioned in the CrowdStrike report"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://www.crowdstrike.com/blog/bears-midst-intrusion-democratic-national-committee/"
		date = "2016-06-14"
	strings:
		$s1 = "pagemgr.exe" wide fullword
	condition:
		uint16(0) == 0x5a4d and 1 of them
}