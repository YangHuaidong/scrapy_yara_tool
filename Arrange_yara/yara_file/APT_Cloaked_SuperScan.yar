rule APT_Cloaked_SuperScan
	{
	meta:
		description = "Looks like a cloaked SuperScan Port Scanner. May be APT group activity."
		date = "2014-07-18"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		score = 50
	strings:
		$s0 = "SuperScan4.exe" wide fullword
		$s1 = "Foundstone Inc." wide fullword
	condition:
		uint16(0) == 0x5a4d and $s0 and $s1 and not filename contains "superscan"
}