rule CN_Honker_HASH_pwhash {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file pwhash.exe"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "689056588f95749f0382d201fac8f58bac393e98"
	strings:
		$s1 = "Example: quarks-pwdump.exe --dump-hash-domain --with-history" fullword ascii /* PEStudio Blacklist: strings */
		$s2 = "quarks-pwdump.exe <options> <NTDS file>" fullword ascii /* PEStudio Blacklist: strings */
	condition:
		uint16(0) == 0x5a4d and filesize < 1000KB and 1 of them
}