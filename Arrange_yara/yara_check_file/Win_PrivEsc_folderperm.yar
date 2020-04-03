rule Win_PrivEsc_folderperm {
	meta:
		description = "Detects a tool that can be used for privilege escalation - file folderperm.ps1"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "http://www.greyhathacker.net/?p=738"
		date = "2016-06-02"
		score = 80
		hash1 = "1aa87df34826b1081c40bb4b702750587b32d717ea6df3c29715eb7fc04db755"
	strings:
		$x1 = "# powershell.exe -executionpolicy bypass -file folderperm.ps1" fullword ascii
		$x2 = "Write-Host \"[i] Dummy test file used to test access was not outputted:\" $filetocopy" fullword ascii
		$x3 = "Write-Host -foregroundColor Red \"      Access denied :\" $myarray[$i] " fullword ascii
	condition:
		1 of them
}