rule IronTiger_ReadPWD86
{
	meta:
		author = "Cyber Safety Solutions, Trend Micro"
		description = "Iron Tiger Malware - ReadPWD86"
		reference = "http://goo.gl/T5fSJC"
	strings:
		$str1 = "Fail To Load LSASRV" nocase wide ascii
		$str2 = "Fail To Search LSASS Data" nocase wide ascii
		$str3 = "User Principal" nocase wide ascii
	condition:
		uint16(0) == 0x5a4d and (all of ($str*))
}