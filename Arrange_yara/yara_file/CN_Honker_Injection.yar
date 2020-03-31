rule CN_Honker_Injection {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file Injection.exe"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "3484ed16e6f9e0d603cbc5cb44e46b8b7e775d35"
	strings:
		$s0 = "http://127.0.0.1/6kbbs/bank.asp" fullword ascii /* PEStudio Blacklist: strings */
		$s7 = "jmPost.asp" fullword wide /* PEStudio Blacklist: strings */
	condition:
		uint16(0) == 0x5a4d and filesize < 220KB and all of them
}