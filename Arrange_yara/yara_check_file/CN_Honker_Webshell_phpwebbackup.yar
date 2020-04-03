rule CN_Honker_Webshell_phpwebbackup {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file phpwebbackup.php"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "c788cb280b7ad0429313837082fe84e9a49efab6"
	strings:
		$s0 = "<?php // Code By isosky www.nbst.org" fullword ascii
		$s2 = "$OOO0O0O00=__FILE__;$OOO000000=urldecode('" ascii /* PEStudio Blacklist: strings */
	condition:
		uint16(0) == 0x3f3c and filesize < 67KB and all of them
}