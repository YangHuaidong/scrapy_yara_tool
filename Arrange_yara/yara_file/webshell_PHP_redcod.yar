rule webshell_PHP_redcod {
	meta:
		description = "Web Shell - file redcod.php"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "5c1c8120d82f46ff9d813fbe3354bac5"
	strings:
		$s0 = "H8p0bGFOEy7eAly4h4E4o88LTSVHoAglJ2KLQhUw" fullword
		$s1 = "HKP7dVyCf8cgnWFy8ocjrP5ffzkn9ODroM0/raHm" fullword
	condition:
		all of them
}