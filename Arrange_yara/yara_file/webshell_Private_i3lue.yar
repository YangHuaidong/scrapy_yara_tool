rule webshell_Private_i3lue {
	meta:
		description = "Web Shell - file Private-i3lue.php"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "13f5c7a035ecce5f9f380967cf9d4e92"
	strings:
		$s8 = "case 15: $image .= \"\\21\\0\\"
	condition:
		all of them
}