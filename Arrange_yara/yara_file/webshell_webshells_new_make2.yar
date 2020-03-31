rule webshell_webshells_new_make2 {
	meta:
		description = "Web shells - generated from file make2.php"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		date = "2014/03/28"
		hash = "9af195491101e0816a263c106e4c145e"
		score = 50
	strings:
		$s1 = "error_reporting(0);session_start();header(\"Content-type:text/html;charset=utf-8"
	condition:
		all of them
}