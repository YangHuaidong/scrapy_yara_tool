rule PHP_Backdoor_v1 {
	meta:
		description = "Webshells Auto-generated - file PHP Backdoor v1.php"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		hash = "0506ba90759d11d78befd21cabf41f3d"
	strings:
		$s5 = "echo\"<form method=\\\"POST\\\" action=\\\"\".$_SERVER['PHP_SELF'].\"?edit=\".$th"
		$s8 = "echo \"<a href=\\\"\".$_SERVER['PHP_SELF'].\"?proxy"
	condition:
		all of them
}