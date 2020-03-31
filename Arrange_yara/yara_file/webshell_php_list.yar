rule webshell_php_list {
	meta:
		description = "Web Shell - file list.php"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "922b128ddd90e1dc2f73088956c548ed"
	strings:
		$s1 = "// list.php = Directory & File Listing" fullword
		$s2 = "    echo \"( ) <a href=?file=\" . $fichero . \"/\" . $filename . \">\" . $filena"
		$s9 = "// by: The Dark Raver" fullword
	condition:
		1 of them
}