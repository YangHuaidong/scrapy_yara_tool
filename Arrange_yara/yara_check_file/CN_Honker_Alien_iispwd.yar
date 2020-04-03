rule CN_Honker_Alien_iispwd {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file iispwd.vbs"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "5d157a1b9644adbe0b28c37d4022d88a9f58cedb"
	strings:
		$s0 = "set IIs=objservice.GetObject(\"IIsWebServer\",childObjectName)" fullword ascii /* PEStudio Blacklist: strings */
		$s1 = "wscript.echo \"from : http://www.xxx.com/\" &vbTab&vbCrLf" fullword ascii /* PEStudio Blacklist: strings */
	condition:
		filesize < 3KB and all of them
}