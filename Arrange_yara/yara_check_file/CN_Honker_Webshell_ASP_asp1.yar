rule CN_Honker_Webshell_ASP_asp1 {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file asp1.txt"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "78b5889b363043ed8a60bed939744b4b19503552"
	strings:
		$s1 = "SItEuRl=" ascii
		$s2 = "<%@ LANGUAGE = VBScript.Encode %><%" fullword ascii /* PEStudio Blacklist: strings */
		$s3 = "Server.ScriptTimeout=" ascii /* PEStudio Blacklist: strings */
	condition:
		filesize < 200KB and all of them
}