rule DTools2_02_DTools {
	meta:
		description = "Chinese Hacktool Set - file DTools.exe"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "9f99771427120d09ec7afa3b21a1cb9ed720af12"
	strings:
		$s0 = "kernel32.dll" ascii
		$s1 = "TSETPASSWORDFORM" fullword wide
		$s2 = "TGETNTUSERNAMEFORM" fullword wide
		$s3 = "TPORTFORM" fullword wide
		$s4 = "ShellFold" fullword ascii
		$s5 = "DefaultPHotLigh" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 2000KB and all of them
}