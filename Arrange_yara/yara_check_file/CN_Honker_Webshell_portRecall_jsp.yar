rule CN_Honker_Webshell_portRecall_jsp {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file jsp.txt"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "65e8e4d13ad257c820cad12eef853c6d0134fce8"
	strings:
		$s0 = "lcx.jsp?localIP=202.91.246.59&localPort=88&remoteIP=218.232.111.187&remotePort=2" ascii /* PEStudio Blacklist: strings */
	condition:
		filesize < 1KB and all of them
}