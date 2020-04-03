rule CN_Honker_Webshell_ASPX_sniff {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file sniff.txt"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "e246256696be90189e6d50a4ebc880e6d9e28dfd"
	strings:
		$s1 = "IPHostEntry HosyEntry = Dns.GetHostEntry((Dns.GetHostName()));" fullword ascii /* PEStudio Blacklist: strings */
		$s2 = "if (!logIt && my_s_smtp && (dport == 25 || sport == 25))" fullword ascii /* PEStudio Blacklist: strings */
	condition:
		filesize < 91KB and all of them
}