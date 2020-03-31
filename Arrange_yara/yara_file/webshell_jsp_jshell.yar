rule webshell_jsp_jshell {
	meta:
		description = "Web Shell - file jshell.jsp"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "124b22f38aaaf064cef14711b2602c06"
	strings:
		$s0 = "kXpeW[\"" fullword
		$s4 = "[7b:g0W@W<" fullword
		$s5 = "b:gHr,g<" fullword
		$s8 = "RhV0W@W<" fullword
		$s9 = "S_MR(u7b" fullword
	condition:
		all of them
}