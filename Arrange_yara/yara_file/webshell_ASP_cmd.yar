rule webshell_ASP_cmd {
	meta:
		description = "Web Shell - file cmd.asp"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "97af88b478422067f23b001dd06d56a9"
	strings:
		$s0 = "<%= \"\\\\\" & oScriptNet.ComputerName & \"\\\" & oScriptNet.UserName %>" fullword
	condition:
		all of them
}