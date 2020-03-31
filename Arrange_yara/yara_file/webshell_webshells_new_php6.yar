rule webshell_webshells_new_php6 {
	meta:
		description = "Web shells - generated from file php6.php"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		date = "2014/03/28"
		score = 70
		hash = "ea75280224a735f1e445d244acdfeb7b"
	strings:
		$s1 = "array_map(\"asx73ert\",(ar"
		$s3 = "preg_replace(\"/[errorpage]/e\",$page,\"saft\");" fullword
		$s4 = "shell.php?qid=zxexp  " fullword
	condition:
		1 of them
}