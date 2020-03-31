rule FSO_s_ajan {
	meta:
		description = "Webshells Auto-generated - file ajan.asp"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		hash = "22194f8c44524f80254e1b5aec67b03e"
	strings:
		$s4 = "entrika.write \"BinaryStream.SaveToFile"
	condition:
		all of them
}