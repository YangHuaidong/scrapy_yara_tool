rule webshell_php_up {
	meta:
		description = "Web Shell - file up.php"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "7edefb8bd0876c41906f4b39b52cd0ef"
	strings:
		$s0 = "copy($HTTP_POST_FILES['userfile']['tmp_name'], $_POST['remotefile']);" fullword
		$s3 = "if(is_uploaded_file($HTTP_POST_FILES['userfile']['tmp_name'])) {" fullword
		$s8 = "echo \"Uploaded file: \" . $HTTP_POST_FILES['userfile']['name'];" fullword
	condition:
		2 of them
}