rule CN_Honker_Webshell_ASP_asp2 {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file asp2.txt"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "b3ac478e72a0457798a3532f6799adeaf4a7fc87"
	strings:
		$s1 = "<%=server.mappath(request.servervariables(\"script_name\"))%>" fullword ascii /* PEStudio Blacklist: strings */
		$s2 = "webshell</font> <font color=#00FF00>" fullword ascii /* PEStudio Blacklist: strings */
		$s3 = "Userpwd = \"admin\"   'User Password" fullword ascii /* PEStudio Blacklist: strings */
	condition:
		filesize < 10KB and all of them
}