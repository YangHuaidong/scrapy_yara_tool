rule FSO_s_indexer {
	meta:
		description = "Webshells Auto-generated - file indexer.asp"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		hash = "135fc50f85228691b401848caef3be9e"
	strings:
		$s3 = "<td>Nereye :<td><input type=\"text\" name=\"nereye\" size=25></td><td><input type=\"r"
	condition:
		all of them
}