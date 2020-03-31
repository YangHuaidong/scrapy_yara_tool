rule kappfree {
	meta:
		description = "Chinese Hacktool Set - file kappfree.dll"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "e57e79f190f8a24ca911e6c7e008743480c08553"
	strings:
		$s1 = "Bienvenue dans un processus distant" fullword wide
		$s2 = "kappfree.dll" fullword ascii
		$s3 = "kappfree de mimikatz pour Windows (anti AppLocker)" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 200KB and all of them
}