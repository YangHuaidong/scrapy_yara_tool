rule WebShell_reader_asp_php {
	meta:
		description = "PHP Webshells Github Archive - file reader.asp.php.txt"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		hash = "70656f3495e2b3ad391a77d5208eec0fb9e2d931"
	strings:
		$s5 = "ster\" name=submit> </Font> &nbsp; &nbsp; &nbsp; <a href=mailto:mailbomb@hotmail"
		$s12 = " HACKING " fullword
		$s16 = "FONT-WEIGHT: bold; BACKGROUND: #ffffff url('images/cellpic1.gif'); TEXT-INDENT: "
		$s20 = "PADDING-RIGHT: 8px; PADDING-LEFT: 8px; FONT-WEIGHT: bold; FONT-SIZE: 11px; BACKG"
	condition:
		3 of them
}