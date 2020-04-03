rule Hacktool_This_Cruft {
	meta:
		description = "Detects string 'This cruft' often used in hack tools like netcat or cryptcat and also mentioned in Project Sauron report"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://goo.gl/eFoP4A"
		date = "2016-08-08"
		score = 60
	strings:
		$x1 = "This cruft" fullword
	condition:
		( uint16(0) == 0x5a4d and filesize < 200KB and $x1 )
}