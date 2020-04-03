rule FourElementSword_Config_File {
	meta:
		description = "Detects FourElementSword Malware - file f05cd0353817bf6c2cab396181464c31c352d6dea07e2d688def261dd6542b27"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://www.arbornetworks.com/blog/asert/four-element-sword-engagement/"
		date = "2016-04-18"
		hash = "f05cd0353817bf6c2cab396181464c31c352d6dea07e2d688def261dd6542b27"
	strings:
		$s0 = "01,,hccutils.dll,2" fullword ascii
		$s1 = "RegisterDlls=OurDll" fullword ascii
		$s2 = "[OurDll]" fullword ascii
		$s3 = "[DefaultInstall]" fullword ascii /* Goodware String - occured 16 times */
		$s4 = "Signature=\"$Windows NT$\"" fullword ascii /* Goodware String - occured 26 times */
	condition:
		4 of them
}