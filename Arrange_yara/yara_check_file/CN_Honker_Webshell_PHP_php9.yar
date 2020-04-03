rule CN_Honker_Webshell_PHP_php9 {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file php9.txt"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "cd3962b1dba9f1b389212e38857568b69ca76725"
	strings:
		$s1 = "Str[17] = \"select shell('c:\\windows\\system32\\cmd.exe /c net user b4che10r ab" ascii /* PEStudio Blacklist: strings */
	condition:
		filesize < 1087KB and all of them
}