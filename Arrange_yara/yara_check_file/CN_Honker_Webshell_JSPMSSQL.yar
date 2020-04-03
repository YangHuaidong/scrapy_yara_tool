rule CN_Honker_Webshell_JSPMSSQL {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file JSPMSSQL.txt"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "c6b4faecd743d151fe0a4634e37c9a5f6533655f"
	strings:
		$s1 = "<form action=\"?action=operator&cmd=execute\"" fullword ascii /* PEStudio Blacklist: strings */
		$s2 = "String sql = request.getParameter(\"sqlcmd\");" fullword ascii /* PEStudio Blacklist: strings */
	condition:
		filesize < 35KB and all of them
}