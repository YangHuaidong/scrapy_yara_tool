rule FSO_s_phpinj {
	meta:
		description = "Webshells Auto-generated - file phpinj.php"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		hash = "dd39d17e9baca0363cc1c3664e608929"
	strings:
		$s4 = "echo '<a href='.$expurl.'> Click Here to Exploit </a> <br />';"
	condition:
		all of them
}