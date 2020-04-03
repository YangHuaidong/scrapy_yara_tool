rule CN_Honker_Webshell_ASP_web_asp {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file web.asp.txt"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "aebf6530e89af2ad332062c6aae4a8ca91517c76"
	strings:
		$s0 = "<FORM method=post target=_blank>ShellUrl: <INPUT " fullword ascii /* PEStudio Blacklist: strings */
		$s1 = "\" >[Copy code]</a> 4ngr7&nbsp; &nbsp;</td>" fullword ascii
	condition:
		filesize < 13KB and all of them
}