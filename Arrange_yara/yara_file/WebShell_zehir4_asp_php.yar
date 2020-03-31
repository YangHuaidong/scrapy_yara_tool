rule WebShell_zehir4_asp_php {
	meta:
		description = "PHP Webshells Github Archive - file zehir4.asp.php.txt"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		hash = "1d9b78b5b14b821139541cc0deb4cbbd994ce157"
	strings:
		$s4 = "response.Write \"<title>zehir3 --> powered by zehir &lt;zehirhacker@hotmail.com&"
		$s11 = "frames.byZehir.document.execCommand("
		$s15 = "frames.byZehir.document.execCommand(co"
	condition:
		2 of them
}