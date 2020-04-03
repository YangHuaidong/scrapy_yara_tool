rule FSO_s_tool {
	meta:
		description = "Webshells Auto-generated - file tool.asp"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		hash = "3a1e1e889fdd974a130a6a767b42655b"
	strings:
		$s7 = "\"\"%windir%\\\\calc.exe\"\")"
	condition:
		all of them
}