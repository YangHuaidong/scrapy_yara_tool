rule CN_Honker_Webshell_ASP_asp3 {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file asp3.txt"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "87c5a76989bf08da5562e0b75c196dcb3087a27b"
	strings:
		$s1 = "if shellpath=\"\" then shellpath = \"cmd.exe\"" fullword ascii /* PEStudio Blacklist: strings */
		$s2 = "c.open \"GET\", \"http://127.0.0.1:\" & port & \"/M_Schumacher/upadmin/s3\", Tru" ascii /* PEStudio Blacklist: strings */
	condition:
		filesize < 444KB and all of them
}