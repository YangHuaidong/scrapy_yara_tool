rule FSO_s_indexer_2 {
	meta:
		description = "Webshells Auto-generated - file indexer.asp"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		hash = "135fc50f85228691b401848caef3be9e"
	strings:
		$s5 = "<td>Nerden :<td><input type=\"text\" name=\"nerden\" size=25 value=index.html></td>"
	condition:
		all of them
}