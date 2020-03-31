rule Sofacy_AZZY_Backdoor_Implant_1 {
	meta:
		description = "AZZY Backdoor Implant 4.3 - Sample 1"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://securelist.com/blog/research/72924/sofacy-apt-hits-high-profile-targets-with-updated-toolset/"
		date = "2015-12-04"
		hash = "1bab1a3e0e501d3c14652ecf60870e483ed4e90e500987c35489f17a44fef26c"
	strings:
		$s1 = "\\tf394kv.dll" fullword wide
		$s2 = "DWN_DLL_MAIN.dll" fullword ascii
		$s3 = "?SendDataToServer_2@@YGHPAEKEPAPAEPAK@Z" ascii
		$s4 = "?Applicate@@YGHXZ" ascii
		$s5 = "?k@@YGPAUHINSTANCE__@@PBD@Z" ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 300KB and 2 of them
}