rule CN_Honker_Webshell_PHP_linux {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file linux.txt"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "78339abb4e2bb00fe8a012a0a5b7ffce305f4e06"
	strings:
		$s0 = "<form name=form1 action=exploit.php method=post>" fullword ascii /* PEStudio Blacklist: strings */
		$s1 = "<title>Changing CHMOD Permissions Exploit " fullword ascii
	condition:
		uint16(0) == 0x696c and filesize < 6KB and all of them
}