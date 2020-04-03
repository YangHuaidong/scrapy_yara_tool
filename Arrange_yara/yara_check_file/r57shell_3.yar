rule r57shell_3 {
	meta:
		description = "Webshells Auto-generated - file r57shell.php"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		hash = "87995a49f275b6b75abe2521e03ac2c0"
	strings:
		$s1 = "<b>\".$_POST['cmd']"
	condition:
		all of them
}