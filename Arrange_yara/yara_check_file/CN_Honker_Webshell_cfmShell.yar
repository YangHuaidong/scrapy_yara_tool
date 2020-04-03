rule CN_Honker_Webshell_cfmShell {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file cfmShell.cfm"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "740796909b5d011128b6c54954788d14faea9117"
	strings:
		$s0 = "<cfexecute name=\"C:\\Winnt\\System32\\cmd.exe\"" fullword ascii /* PEStudio Blacklist: strings */
		$s4 = "<cfif FileExists(\"#GetTempDirectory()#foobar.txt\") is \"Yes\">" fullword ascii
	condition:
		filesize < 4KB and all of them
}