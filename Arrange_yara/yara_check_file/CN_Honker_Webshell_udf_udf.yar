rule CN_Honker_Webshell_udf_udf {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file udf.php"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "df63372ccab190f2f1d852f709f6b97a8d9d22b9"
	strings:
		$s1 = "<?php // Source  My : Meiam  " fullword ascii /* PEStudio Blacklist: strings */
		$s2 = "$OOO0O0O00=__FILE__;$OOO000000=urldecode('" ascii /* PEStudio Blacklist: strings */
	condition:
		filesize < 430KB and all of them
}