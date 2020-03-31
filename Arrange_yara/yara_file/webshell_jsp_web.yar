rule webshell_jsp_web {
	meta:
		description = "Web Shell - file web.jsp"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "4bc11e28f5dccd0c45a37f2b541b2e98"
	strings:
		$s0 = "<%@page import=\"java.io.*\"%><%@page import=\"java.net.*\"%><%String t=request."
	condition:
		all of them
}