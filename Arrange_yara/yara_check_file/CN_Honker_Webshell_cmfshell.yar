rule CN_Honker_Webshell_cmfshell {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file cmfshell.cmf"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "b9b2107c946431e4ad1a8f5e53ac05e132935c0e"
	strings:
		$s1 = "<cfexecute name=\"C:\\Winnt\\System32\\cmd.exe\"" fullword ascii /* PEStudio Blacklist: strings */
		$s2 = "<form action=\"<cfoutput>#CGI.SCRIPT_NAME#</cfoutput>\" method=\"post\">" fullword ascii /* PEStudio Blacklist: strings */
	condition:
		filesize < 4KB and all of them
}