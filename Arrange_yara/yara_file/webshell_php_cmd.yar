rule webshell_php_cmd {
	meta:
		description = "Web Shell - file cmd.php"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "c38ae5ba61fd84f6bbbab98d89d8a346"
	strings:
		$s0 = "if($_GET['cmd']) {" fullword
		$s1 = "// cmd.php = Command Execution" fullword
		$s7 = "  system($_GET['cmd']);" fullword
	condition:
		all of them
}