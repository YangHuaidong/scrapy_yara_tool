rule CN_Honker_struts2_catbox {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file catbox.exe"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "ee8fbd91477e056aef34fce3ade474cafa1a4304"
	strings:
		$s6 = "'Toolmao box by gainover www.toolmao.com" fullword ascii
		$s20 = "{external.exeScript(_toolmao_bgscript[i],'javascript',false);}}" fullword ascii /* PEStudio Blacklist: strings */
	condition:
		uint16(0) == 0x5a4d and filesize < 8160KB and all of them
}