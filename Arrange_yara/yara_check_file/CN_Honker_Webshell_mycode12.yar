rule CN_Honker_Webshell_mycode12 {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file mycode12.cfm"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "64be8760be5ab5c2dcf829e3f87d3e50b1922f17"
	strings:
		$s1 = "<cfexecute name=\"cmd.exe\"" fullword ascii /* PEStudio Blacklist: strings */
		$s2 = "<cfoutput>#cmd#</cfoutput>" fullword ascii
	condition:
		filesize < 4KB and all of them
}