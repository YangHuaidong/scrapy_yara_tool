rule CN_Honker_Webshell_cfm_list {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file list.cfm"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "85d445b13d2aef1df3b264c9b66d73f0ff345cec"
	strings:
		$s1 = "<TD><a href=\"javascript:ShowFile('#mydirectory.name#')\">#mydirectory.name#</a>" ascii /* PEStudio Blacklist: strings */
		$s2 = "<TD>#mydirectory.size#</TD>" fullword ascii
	condition:
		filesize < 10KB and all of them
}