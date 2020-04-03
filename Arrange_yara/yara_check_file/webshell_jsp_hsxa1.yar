rule webshell_jsp_hsxa1 {
	meta:
		description = "Web Shell - file hsxa1.jsp"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "5686d5a38c6f5b8c55095af95c2b0244"
	strings:
		$s0 = "<%@ page language=\"java\" pageEncoding=\"gbk\"%><jsp:directive.page import=\"ja"
	condition:
		all of them
}