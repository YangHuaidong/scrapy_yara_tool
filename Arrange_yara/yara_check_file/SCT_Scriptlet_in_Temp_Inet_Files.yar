rule SCT_Scriptlet_in_Temp_Inet_Files {
	meta:
		description = "Detects a scriptlet file in the temporary Internet files (see regsvr32 AppLocker bypass)"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "http://goo.gl/KAB8Jw"
		date = "2016-04-26"
	strings:
		$s1 = "<scriptlet>" fullword ascii nocase
		$s2 = "ActiveXObject(\"WScript.Shell\")" ascii
	condition:
		( uint32(0) == 0x4D583F3C or uint32(0) == 0x6D78F3C ) /* <?XM or <?xm */
		and $s1 and $s2
		and filepath contains "Temporary Internet Files"
}