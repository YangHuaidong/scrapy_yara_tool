rule Sofacy_CollectorStealer_Gen1 {
	meta:
		description = "Generic rule to detect Sofacy Malware Collector Stealer"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://securelist.com/blog/research/72924/sofacy-apt-hits-high-profile-targets-with-updated-toolset/"
		date = "2015-12-04"
		super_rule = 1
		hash1 = "4e4606313c423b681e11110ca5ed3a2b2632ec6c556b7ab9642372ae709555f3"
		hash2 = "92dcb0d8394d0df1064e68d90cd90a6ae5863e91f194cbaac85ec21c202f581f"
	strings:
		$s0 = "NvCpld.dll" fullword ascii
		$s1 = "NvStop" fullword ascii
		$s2 = "NvStart" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 300KB and all of them
}