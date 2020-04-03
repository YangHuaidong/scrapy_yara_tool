rule FourElementSword_fslapi_dll_gui {
	meta:
		description = "Detects FourElementSword Malware - file 2a6ef9dde178c4afe32fe676ff864162f104d85fac2439986de32366625dc083"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://www.arbornetworks.com/blog/asert/four-element-sword-engagement/"
		date = "2016-04-18"
		hash = "2a6ef9dde178c4afe32fe676ff864162f104d85fac2439986de32366625dc083"
	strings:
		$s1 = "fslapi.dll.gui" fullword wide
		$s2 = "ImmGetDefaultIMEWnd" fullword ascii /* Goodware String - occured 64 times */
		$s3 = "RichOX" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 12KB and all of them )
}