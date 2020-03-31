rule KA_uShell {
	meta:
		description = "Webshells Auto-generated - file KA_uShell.php"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		hash = "685f5d4f7f6751eaefc2695071569aab"
	strings:
		$s5 = "if(empty($_SERVER['PHP_AUTH_PW']) || $_SERVER['PHP_AUTH_PW']<>$pass"
		$s6 = "if ($_POST['path']==\"\"){$uploadfile = $_FILES['file']['name'];}"
	condition:
		all of them
}