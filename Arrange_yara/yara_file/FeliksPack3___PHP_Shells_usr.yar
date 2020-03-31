rule FeliksPack3___PHP_Shells_usr {
	meta:
		description = "Webshells Auto-generated - file usr.php"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		hash = "ade3357520325af50c9098dc8a21a024"
	strings:
		$s0 = "<?php $id_info = array('notify' => 'off','sub' => 'aasd','s_name' => 'nurullahor"
	condition:
		all of them
}