rule ProjectM_CrimsonDownloader {
	meta:
		description = "Detects ProjectM Malware - file dc8bd60695070152c94cbeb5f61eca6e4309b8966f1aa9fdc2dd0ab754ad3e4c"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "http://researchcenter.paloaltonetworks.com/2016/03/unit42-projectm-link-found-between-pakistani-actor-and-operation-transparent-tribe/"
		date = "2016-03-26"
		hash = "dc8bd60695070152c94cbeb5f61eca6e4309b8966f1aa9fdc2dd0ab754ad3e4c"
	strings:
		$x1 = "E:\\Projects\\m_project\\main\\mj shoaib"
		$s1 = "\\obj\\x86\\Debug\\secure_scan.pdb" ascii
		$s2 = "secure_scan.exe" fullword wide
		$s3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run|mswall" fullword wide
		$s4 = "secure_scan|mswall" fullword wide
		$s5 = "[Microsoft-Security-Essentials]" fullword wide
	condition:
		( uint16(0) == 0x5a4d and filesize < 400KB and $x1 ) or ( all of them )
}