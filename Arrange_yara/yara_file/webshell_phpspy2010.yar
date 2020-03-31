rule webshell_phpspy2010 {
	meta:
		description = "Web Shell - file phpspy2010.php"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "14ae0e4f5349924a5047fed9f3b105c5"
	strings:
		$s3 = "eval(gzinflate(base64_decode("
		$s5 = "//angel" fullword
		$s8 = "$admin['cookiedomain'] = '';" fullword
	condition:
		all of them
}