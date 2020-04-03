rule IronTiger_EFH3_encoder
{
	meta:
		author = "Cyber Safety Solutions, Trend Micro"
		description = "Iron Tiger EFH3 Encoder"
		reference = "http://goo.gl/T5fSJC"
	strings:
		$str1 = "EFH3 [HEX] [SRCFILE] [DSTFILE]" nocase wide ascii
		$str2 = "123.EXE 123.EFH" nocase wide ascii
		$str3 = "ENCODER: b[i]: = " nocase wide ascii
	condition:
		uint16(0) == 0x5a4d and (any of ($str*))
}