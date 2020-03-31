rule iMHaPFtp {
	meta:
		description = "Webshells Auto-generated - file iMHaPFtp.php"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		hash = "12911b73bc6a5d313b494102abcf5c57"
	strings:
		$s1 = "echo \"\\t<th class=\\\"permission_header\\\"><a href=\\\"$self?{$d}sort=permission$r\\\">"
	condition:
		all of them
}