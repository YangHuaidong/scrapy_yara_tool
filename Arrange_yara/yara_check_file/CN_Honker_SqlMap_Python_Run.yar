rule CN_Honker_SqlMap_Python_Run {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file Run.exe"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "a51479a1c589f17c77d22f6cf90b97011c33145f"
	strings:
		$s1 = ".\\Run.log" fullword ascii
		$s2 = "[root@Hacker~]# Sqlmap " fullword ascii
		$s3 = "%sSqlmap %s" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 30KB and all of them
}