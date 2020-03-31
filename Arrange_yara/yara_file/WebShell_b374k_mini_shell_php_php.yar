rule WebShell_b374k_mini_shell_php_php {
	meta:
		description = "PHP Webshells Github Archive - file b374k-mini-shell-php.php.php"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		hash = "afb88635fbdd9ebe86b650cc220d3012a8c35143"
	strings:
		$s0 = "@error_reporting(0);" fullword
		$s2 = "@eval(gzinflate(base64_decode($code)));" fullword
		$s3 = "@set_time_limit(0); " fullword
	condition:
		all of them
}