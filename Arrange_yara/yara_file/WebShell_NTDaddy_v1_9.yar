rule WebShell_NTDaddy_v1_9 {
	meta:
		description = "PHP Webshells Github Archive - file NTDaddy v1.9.php"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		hash = "79519aa407fff72b7510c6a63c877f2e07d7554b"
	strings:
		$s2 = "|     -obzerve : mr_o@ihateclowns.com |" fullword
		$s6 = "szTempFile = \"C:\\\" & oFileSys.GetTempName( )" fullword
		$s13 = "<form action=ntdaddy.asp method=post>" fullword
		$s17 = "response.write(\"<ERROR: THIS IS NOT A TEXT FILE>\")" fullword
	condition:
		2 of them
}