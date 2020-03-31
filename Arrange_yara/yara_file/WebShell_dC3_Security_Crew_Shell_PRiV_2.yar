rule WebShell_dC3_Security_Crew_Shell_PRiV_2 {
	meta:
		description = "PHP Webshells Github Archive - file dC3 Security Crew Shell PRiV.php"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		hash = "9077eb05f4ce19c31c93c2421430dd3068a37f17"
	strings:
		$s0 = "@rmdir($_GET['file']) or die (\"[-]Error deleting dir!\");" fullword
		$s9 = "header(\"Last-Modified: \".date(\"r\",filemtime(__FILE__)));" fullword
		$s13 = "header(\"Content-type: image/gif\");" fullword
		$s14 = "@copy($file,$to) or die (\"[-]Error copying file!\");" fullword
		$s20 = "if (isset($_GET['rename_all'])) {" fullword
	condition:
		3 of them
}