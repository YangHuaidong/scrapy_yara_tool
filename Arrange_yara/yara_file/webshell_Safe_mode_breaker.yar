rule webshell_Safe_mode_breaker {
	meta:
		description = "Web Shell - file Safe mode breaker.php"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "5bd07ccb1111950a5b47327946bfa194"
	strings:
		$s5 = "preg_match(\"/SAFE\\ MODE\\ Restriction\\ in\\ effect\\..*whose\\ uid\\ is("
		$s6 = "$path =\"{$root}\".((substr($root,-1)!=\"/\") ? \"/\" : NULL)."
	condition:
		1 of them
}