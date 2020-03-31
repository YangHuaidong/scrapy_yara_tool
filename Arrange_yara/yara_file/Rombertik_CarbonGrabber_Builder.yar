rule Rombertik_CarbonGrabber_Builder {
	meta:
		description = "Detects CarbonGrabber alias Rombertik Builder - file Builder.exe"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "http://blogs.cisco.com/security/talos/rombertik"
		date = "2015-05-05"
		hash = "b50ecc0ba3d6ec19b53efe505d14276e9e71285f"
	strings:
		$s0 = "c:\\users\\iden\\documents\\visual studio 2010\\Projects\\FormGrabberBuilderC++" ascii
		$s1 = "Host(www.panel.com): " fullword ascii
		$s2 = "Path(/form/index.php?a=insert): " fullword ascii
		$s3 = "FileName: " fullword ascii
		$s4 = "~Rich8" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 35KB and all of them
}