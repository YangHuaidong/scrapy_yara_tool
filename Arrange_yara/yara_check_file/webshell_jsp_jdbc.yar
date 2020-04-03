rule webshell_jsp_jdbc {
	meta:
		description = "Web Shell - file jdbc.jsp"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "23b0e6f91a8f0d93b9c51a2a442119ce"
	strings:
		$s4 = "String cs = request.getParameter(\"z0\")==null?\"gbk\": request.getParameter(\"z"
	condition:
		all of them
}