rule FourElementSword_ResN32DLL {
	meta:
		description = "Detects FourElementSword Malware - file bf1b00b7430899d33795ef3405142e880ef8dcbda8aab0b19d80875a14ed852f"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://www.arbornetworks.com/blog/asert/four-element-sword-engagement/"
		date = "2016-04-18"
		hash = "bf1b00b7430899d33795ef3405142e880ef8dcbda8aab0b19d80875a14ed852f"
	strings:
		$s1 = "\\Release\\BypassUAC.pdb" ascii
		$s2 = "\\ResN32.dll" fullword wide
		$s3 = "Eupdate" fullword wide
	condition:
		all of them
}