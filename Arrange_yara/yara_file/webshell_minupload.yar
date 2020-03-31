rule webshell_minupload {
	meta:
		description = "Web Shell - file minupload.jsp"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "ec905a1395d176c27f388d202375bdf9"
	strings:
		$s0 = "<input type=\"submit\" name=\"btnSubmit\" value=\"Upload\">   " fullword
		$s9 = "String path=new String(request.getParameter(\"path\").getBytes(\"ISO-8859"
	condition:
		all of them
}