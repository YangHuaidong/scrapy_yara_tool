rule Duqu2_Sample4 {
	meta:
		description = "Detects Duqu2 Malware"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://securelist.com/blog/research/70504/the-mystery-of-duqu-2-0-a-sophisticated-cyberespionage-actor-returns/"
		date = "2016-07-02"
		score = 80
		hash1 = "3536df7379660d931256b3cf49be810c0d931c3957c464d75e4cba78ba3b92e3"
	strings:
		$x1 = "SELECT `Data` FROM `Binary` WHERE `Name`='CryptHash%i'" fullword wide
		$s2 = "SELECT `UserName`, `Password`, `Attributes` FROM `CustomUserAccounts`" fullword wide
		$s3 = "SELECT `UserName` FROM `CustomUserAccounts`" fullword wide
		$s4 = "ProcessUserAccounts" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 30KB and 1 of ($x*) ) or ( all of them )
}