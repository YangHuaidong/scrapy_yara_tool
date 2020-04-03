rule CN_Honker_Webshell_PHP_php2 {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file php2.txt"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "bf12e1d741075cd1bd324a143ec26c732a241dea"
	strings:
		$s1 = "$OOO0O0O00=__FILE__;$OOO000000=urldecode('" ascii /* PEStudio Blacklist: strings */
		$s2 = "<?php // Black" fullword ascii
	condition:
		filesize < 12KB and all of them
}