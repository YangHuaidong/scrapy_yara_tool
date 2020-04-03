rule CN_Honker_Webshell_portRecall_jsp2 {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file jsp2.txt"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "412ed15eb0d24298ba41731502018800ffc24bfc"
	strings:
		$s0 = "final String remoteIP =request.getParameter(\"remoteIP\");" fullword ascii /* PEStudio Blacklist: strings */
		$s4 = "final String localIP = request.getParameter(\"localIP\");" fullword ascii /* PEStudio Blacklist: strings */
		$s20 = "final String localPort = \"3390\";//request.getParameter(\"localPort\");" fullword ascii /* PEStudio Blacklist: strings */
	condition:
		filesize < 23KB and all of them
}