rule simple_cmd_html {
	meta:
		description = "Semi-Auto-generated  - file simple_cmd.html.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "c6381412df74dbf3bcd5a2b31522b544"
	strings:
		$s1 = "<title>G-Security Webshell</title>" fullword
		$s2 = "<input type=TEXT name=\"-cmd\" size=64 value=\"<?=$cmd?>\" " fullword
		$s3 = "<? if($cmd != \"\") print Shell_Exec($cmd);?>" fullword
		$s4 = "<? $cmd = $_REQUEST[\"-cmd\"];?>" fullword
	condition:
		all of them
}