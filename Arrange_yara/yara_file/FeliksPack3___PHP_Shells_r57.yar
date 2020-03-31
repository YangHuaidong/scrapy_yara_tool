rule FeliksPack3___PHP_Shells_r57 {
	meta:
		description = "Webshells Auto-generated - file r57.php"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		hash = "903908b77a266b855262cdbce81c3f72"
	strings:
		$s1 = "$sql = \"LOAD DATA INFILE \\\"\".$_POST['test3_file']."
	condition:
		all of them
}