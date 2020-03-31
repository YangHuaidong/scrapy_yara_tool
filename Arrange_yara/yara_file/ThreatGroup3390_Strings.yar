rule ThreatGroup3390_Strings {
	meta:
		description = "Threat Group 3390 APT - Strings"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "http://snip.ly/giNB"
		date = "2015-08-06"
		score = 60
	strings:
		$s1 = "\"cmd\" /c cd /d \"c:\\Windows\\Temp\\\"&copy" ascii
		$s2 = "svchost.exe a -k -r -s -m5 -v1024000 -padmin-windows2014"
		$s3 = "ren *.rar *.zip" fullword ascii
		$s4 = "c:\\temp\\ipcan.exe" fullword ascii
		$s5 = "<%eval(Request.Item(\"admin-na-google123!@#" ascii
	condition:
		1 of them and filesize < 30KB
}