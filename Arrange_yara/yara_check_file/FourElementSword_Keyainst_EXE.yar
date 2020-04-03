rule FourElementSword_Keyainst_EXE {
	meta:
		description = "Detects FourElementSword Malware - file cf717a646a015ee72f965488f8df2dd3c36c4714ccc755c295645fe8d150d082"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://www.arbornetworks.com/blog/asert/four-element-sword-engagement/"
		date = "2016-04-18"
		hash = "cf717a646a015ee72f965488f8df2dd3c36c4714ccc755c295645fe8d150d082"
	strings:
		$x1 = "C:\\ProgramData\\Keyainst.exe" fullword ascii
		$s1 = "ShellExecuteA" fullword ascii /* Goodware String - occured 266 times */
		$s2 = "GetStartupInfoA" fullword ascii /* Goodware String - occured 2573 times */
		$s3 = "SHELL32.dll" fullword ascii /* Goodware String - occured 3233 times */
	condition:
		( uint16(0) == 0x5a4d and filesize < 48KB and $x1 ) or ( all of them )
}