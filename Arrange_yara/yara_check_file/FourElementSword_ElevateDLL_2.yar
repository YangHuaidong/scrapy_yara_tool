rule FourElementSword_ElevateDLL_2 {
	meta:
		description = "Detects FourElementSword Malware - file 9c23febc49c7b17387767844356d38d5578727ee1150956164883cf555fe7f95"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://www.arbornetworks.com/blog/asert/four-element-sword-engagement/"
		date = "2016-04-18"
		hash = "9c23febc49c7b17387767844356d38d5578727ee1150956164883cf555fe7f95"
	strings:
		$s1 = "Elevate.dll" fullword ascii
		$s2 = "GetSomeF" fullword ascii
		$s3 = "GetNativeSystemInfo" fullword ascii /* Goodware String - occured 530 times */
	condition:
		( uint16(0) == 0x5a4d and filesize < 25KB and $s1 ) or ( all of them )
}