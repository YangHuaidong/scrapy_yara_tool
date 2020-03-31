rule CN_Honker_Codeeer_Explorer {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file Codeeer Explorer.exe"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "f32e05f3fefbaa2791dd750e4a3812581ce0f205"
	strings:
		$s2 = "Codeeer Explorer.exe" fullword wide /* PEStudio Blacklist: strings */
		$s12 = "webBrowser1_ProgressChanged" fullword ascii /* PEStudio Blacklist: strings */
	condition:
		uint16(0) == 0x5a4d and filesize < 470KB and all of them
}