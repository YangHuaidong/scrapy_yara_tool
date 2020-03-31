rule webshell_PHP_g00nv13 {
	meta:
		description = "Web Shell - file g00nv13.php"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "35ad2533192fe8a1a76c3276140db820"
	strings:
		$s1 = "case \"zip\": case \"tar\": case \"rar\": case \"gz\": case \"cab\": cas"
		$s4 = "if(!($sqlcon = @mysql_connect($_SESSION['sql_host'] . ':' . $_SESSION['sql_p"
	condition:
		all of them
}