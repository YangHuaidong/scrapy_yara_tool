rule dbgiis6cli {
	meta:
		description = "Webshells Auto-generated - file dbgiis6cli.exe"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		hash = "3044dceb632b636563f66fee3aaaf8f3"
	strings:
		$s0 = "User-Agent: Mozilla/4.0 (compatible; MSIE 5.01; Windows NT 5.0)"
		$s5 = "###command:(NO more than 100 bytes!)"
	condition:
		all of them
}