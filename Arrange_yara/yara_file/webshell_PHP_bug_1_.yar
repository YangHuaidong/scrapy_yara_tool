rule webshell_PHP_bug_1_ {
	meta:
		description = "Web Shell - file bug (1).php"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "91c5fae02ab16d51fc5af9354ac2f015"
	strings:
		$s0 = "@include($_GET['bug']);" fullword
	condition:
		all of them
}