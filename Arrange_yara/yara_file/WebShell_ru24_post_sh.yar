rule WebShell_ru24_post_sh {
	meta:
		description = "PHP Webshells Github Archive - file ru24_post_sh.php"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		hash = "d2c18766a1cd4dda928c12ff7b519578ccec0769"
	strings:
		$s1 = "http://www.ru24-team.net" fullword
		$s4 = "if ((!$_POST['cmd']) || ($_POST['cmd']==\"\")) { $_POST['cmd']=\"id;pwd;uname -a"
		$s6 = "Ru24PostWebShell"
		$s7 = "Writed by DreAmeRz" fullword
		$s9 = "$function=passthru; // system, exec, cmd" fullword
	condition:
		1 of them
}