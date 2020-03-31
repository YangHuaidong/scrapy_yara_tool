rule webshell_php_404 {
	meta:
		description = "Web Shell - file 404.php"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "ced050df5ca42064056a7ad610a191b3"
	strings:
		$s0 = "$pass = md5(md5(md5($pass)));" fullword
	condition:
		all of them
}