rule CN_Honker_Webshell_cfm_xl {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file xl.cfm"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "49c3d16ee970945367a7d6ae86b7ade7cb3b5447"
	strings:
		$s0 = "<input name=\"DESTINATION\" value=\"" ascii /* PEStudio Blacklist: strings */
		$s1 = "<CFFILE ACTION=\"Write\" FILE=\"#Form.path#\" OUTPUT=\"#Form.cmd#\">" fullword ascii
	condition:
		uint16(0) == 0x433c and filesize < 13KB and all of them
}