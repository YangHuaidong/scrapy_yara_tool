rule IronTiger_NBDDos_Gh0stvariant_dropper
{
	meta:
		author = "Cyber Safety Solutions, Trend Micro"
		description = "Iron Tiger Malware - NBDDos Gh0stvariant Dropper"
		reference = "http://goo.gl/T5fSJC"
	strings:
		$str1 = "This service can't be stoped." nocase wide ascii
		$str2 = "Provides support for media palyer" nocase wide ascii
		$str4 = "CreaetProcess Error" nocase wide ascii
		$bla1 = "Kill You" nocase wide ascii
		$bla2 = "%4.2f GB" nocase wide ascii
	condition:
		uint16(0) == 0x5a4d and ((any of ($str*)) or (all of ($bla*)))
}