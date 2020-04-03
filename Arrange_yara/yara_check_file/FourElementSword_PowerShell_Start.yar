rule FourElementSword_PowerShell_Start {
	meta:
		description = "Detects FourElementSword Malware - file 9b6053e784c5762fdb9931f9064ba6e52c26c2d4b09efd6ff13ca87bbb33c692"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://www.arbornetworks.com/blog/asert/four-element-sword-engagement/"
		date = "2016-04-18"
		hash = "9b6053e784c5762fdb9931f9064ba6e52c26c2d4b09efd6ff13ca87bbb33c692"
	strings:
		$s0 = "start /min powershell C:\\\\ProgramData\\\\wget.exe" ascii
		$s1 = "start /min powershell C:\\\\ProgramData\\\\iuso.exe" fullword ascii
	condition:
		1 of them
}