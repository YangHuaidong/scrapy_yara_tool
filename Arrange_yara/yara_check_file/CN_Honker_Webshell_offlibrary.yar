rule CN_Honker_Webshell_offlibrary {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file offlibrary.php"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "eb5275f99211106ae10a23b7e565d208a94c402b"
	strings:
		$s0 = "';$i=$g->query(\"SELECT SUBSTRING_INDEX(CURRENT_USER, '@', 1) AS User, SUBSTRING" ascii /* PEStudio Blacklist: strings */
		$s12 = "if(jushRoot){var script=document.createElement('script');script.src=jushRoot+'ju" ascii /* PEStudio Blacklist: strings */
	condition:
		filesize < 1005KB and all of them
}