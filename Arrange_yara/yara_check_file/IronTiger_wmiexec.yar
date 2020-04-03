rule IronTiger_wmiexec
{
	meta:
		author = "Cyber Safety Solutions, Trend Micro"
		description = "Iron Tiger Tool - wmi.vbs detection"
		reference = "http://goo.gl/T5fSJC"
	strings:
		$str1 = "Temp Result File , Change it to where you like" nocase wide ascii
		$str2 = "wmiexec" nocase wide ascii
		$str3 = "By. Twi1ight" nocase wide ascii
		$str4 = "[both mode] ,delay TIME to read result" nocase wide ascii
		$str5 = "such as nc.exe or Trojan" nocase wide ascii
		$str6 = "+++shell mode+++" nocase wide ascii
		$str7 = "win2008 fso has no privilege to delete file" nocase wide ascii
	condition:
		2 of ($str*)
}