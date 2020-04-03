rule IronTiger_GetPassword_x64
{
	meta:
		author = "Cyber Safety Solutions, Trend Micro"
		description = "Iron Tiger Malware - GetPassword x64"
		reference = "http://goo.gl/T5fSJC"
	strings:
		$str1 = "(LUID ERROR)" nocase wide ascii
		$str2 = "Users\\K8team\\Desktop\\GetPassword" nocase wide ascii
		$str3 = "Debug x64\\GetPassword.pdb" nocase wide ascii
		$bla1 = "Authentication Package:" nocase wide ascii
		$bla2 = "Authentication Domain:" nocase wide ascii
		$bla3 = "* Password:" nocase wide ascii
		$bla4 = "Primary User:" nocase wide ascii
	condition:
		uint16(0) == 0x5a4d and ((any of ($str*)) or (all of ($bla*)))
}