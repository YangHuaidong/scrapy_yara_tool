rule WebShell_c99_madnet {
	meta:
		description = "PHP Webshells Github Archive - file c99_madnet.php"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		hash = "17613df393d0a99fd5bea18b2d4707f566cff219"
	strings:
		$s0 = "$md5_pass = \"\"; //If no pass then hash" fullword
		$s1 = "eval(gzinflate(base64_decode('"
		$s2 = "$pass = \"pass\";  //Pass" fullword
		$s3 = "$login = \"user\"; //Login" fullword
		$s4 = "             //Authentication" fullword
	condition:
		all of them
}