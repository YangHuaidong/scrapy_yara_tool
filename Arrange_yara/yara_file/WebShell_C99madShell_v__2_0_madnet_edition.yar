rule WebShell_C99madShell_v__2_0_madnet_edition {
	meta:
		description = "PHP Webshells Github Archive - file C99madShell v. 2.0 madnet edition.php"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		hash = "f99f8228eb12746847f54bad45084f19d1a7e111"
	strings:
		$s0 = "$md5_pass = \"\"; //If no pass then hash" fullword
		$s1 = "eval(gzinflate(base64_decode('"
		$s2 = "$pass = \"\";  //Pass" fullword
		$s3 = "$login = \"\"; //Login" fullword
		$s4 = "//Authentication" fullword
	condition:
		all of them
}