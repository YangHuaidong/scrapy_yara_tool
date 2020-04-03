rule webshell_jsp_inback3 {
	meta:
		description = "Web Shell - file inback3.jsp"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "ea5612492780a26b8aa7e5cedd9b8f4e"
	strings:
		$s0 = "<%if(request.getParameter(\"f\")!=null)(new java.io.FileOutputStream(application"
	condition:
		all of them
}