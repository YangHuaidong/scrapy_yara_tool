rule WebShell_simple_cmd {
	meta:
		description = "PHP Webshells Github Archive - file simple_cmd.php"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		hash = "466a8caf03cdebe07aa16ad490e54744f82e32c2"
	strings:
		$s1 = "<input type=TEXT name=\"-cmd\" size=64 value=\"<?=$cmd?>\" " fullword
		$s2 = "<title>G-Security Webshell</title>" fullword
		$s4 = "<? if($cmd != \"\") print Shell_Exec($cmd);?>" fullword
		$s6 = "<? $cmd = $_REQUEST[\"-cmd\"];?>" fullword
	condition:
		1 of them
}