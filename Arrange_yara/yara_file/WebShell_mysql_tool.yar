rule WebShell_mysql_tool {
	meta:
		description = "PHP Webshells Github Archive - file mysql_tool.php"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		hash = "c9cf8cafcd4e65d1b57fdee5eef98f0f2de74474"
	strings:
		$s12 = "$dump .= \"-- Dumping data for table '$table'\\n\";" fullword
		$s20 = "$dump .= \"CREATE TABLE $table (\\n\";" fullword
	condition:
		2 of them
}