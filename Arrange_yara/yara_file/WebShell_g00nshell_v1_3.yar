rule WebShell_g00nshell_v1_3 {
	meta:
		description = "PHP Webshells Github Archive - file g00nshell-v1.3.php"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		hash = "70fe072e120249c9e2f0a8e9019f984aea84a504"
	strings:
		$s10 = "#To execute commands, simply include ?cmd=___ in the url. #" fullword
		$s15 = "$query = \"SHOW COLUMNS FROM \" . $_GET['table'];" fullword
		$s16 = "$uakey = \"724ea055b975621b9d679f7077257bd9\"; // MD5 encoded user-agent" fullword
		$s17 = "echo(\"<form method='GET' name='shell'>\");" fullword
		$s18 = "echo(\"<form method='post' action='?act=sql'>\");" fullword
	condition:
		2 of them
}