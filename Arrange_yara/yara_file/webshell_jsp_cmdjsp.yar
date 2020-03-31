rule webshell_jsp_cmdjsp {
	meta:
		description = "Web Shell - file cmdjsp.jsp"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "b815611cc39f17f05a73444d699341d4"
	strings:
		$s5 = "<FORM METHOD=GET ACTION='cmdjsp.jsp'>" fullword
	condition:
		all of them
}