rule CN_Honker_Webshell_assembly {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file assembly.asp"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "2bcb4d22758b20df6b9135d3fb3c8f35a9d9028e"
	strings:
		$s0 = "response.write oScriptlhn.exec(\"cmd.exe /c\" & request(\"c\")).stdout.readall" fullword ascii /* PEStudio Blacklist: strings */
	condition:
		filesize < 1KB and all of them
}