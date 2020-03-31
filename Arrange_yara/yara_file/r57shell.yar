rule r57shell {
	meta:
		description = "Webshells Auto-generated - file r57shell.php"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		hash = "8023394542cddf8aee5dec6072ed02b5"
	strings:
		$s11 = " $_POST['cmd']=\"echo \\\"Now script try connect to"
	condition:
		all of them
}