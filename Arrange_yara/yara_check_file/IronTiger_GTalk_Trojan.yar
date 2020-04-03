rule IronTiger_GTalk_Trojan
{
	meta:
		author = "Cyber Safety Solutions, Trend Micro"
		description = "Iron Tiger Malware - GTalk Trojan"
		reference = "http://goo.gl/T5fSJC"
	strings:
		$str1 = "gtalklite.com" nocase wide ascii
		$str2 = "computer=%s&lanip=%s&uid=%s&os=%s&data=%s" nocase wide ascii
		$str3 = "D13idmAdm" nocase wide ascii
		$str4 = "Error: PeekNamedPipe failed with %i" nocase wide ascii
	condition:
		uint16(0) == 0x5a4d and (2 of ($str*))
}