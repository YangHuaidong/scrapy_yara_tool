rule WebShell_php_webshells_pws {
	meta:
		description = "PHP Webshells Github Archive - file pws.php"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		hash = "7a405f1c179a84ff8ac09a42177a2bcd8a1a481b"
	strings:
		$s6 = "if ($_POST['cmd']){" fullword
		$s7 = "$cmd = $_POST['cmd'];" fullword
		$s10 = "echo \"FILE UPLOADED TO $dez\";" fullword
		$s11 = "if (file_exists($uploaded)) {" fullword
		$s12 = "copy($uploaded, $dez);" fullword
		$s17 = "passthru($cmd);" fullword
	condition:
		4 of them
}