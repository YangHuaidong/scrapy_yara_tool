rule FSO_s_ntdaddy {
	meta:
		description = "Webshells Auto-generated - file ntdaddy.asp"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		hash = "f6262f3ad9f73b8d3e7d9ea5ec07a357"
	strings:
		$s1 = "<input type=\"text\" name=\".CMD\" size=\"45\" value=\"<%= szCMD %>\"> <input type=\"s"
	condition:
		all of them
}