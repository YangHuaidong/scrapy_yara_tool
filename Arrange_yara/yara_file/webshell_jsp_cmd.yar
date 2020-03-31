rule webshell_jsp_cmd {
	meta:
		description = "Web Shell - file cmd.jsp"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "5391c4a8af1ede757ba9d28865e75853"
	strings:
		$s6 = "out.println(\"Command: \" + request.getParameter(\"cmd\") + \"<BR>\");" fullword
	condition:
		all of them
}