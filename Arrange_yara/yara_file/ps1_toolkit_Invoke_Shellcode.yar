rule ps1_toolkit_Invoke_Shellcode {
	meta:
		description = "Auto-generated rule - file Invoke-Shellcode.ps1"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://github.com/vysec/ps1-toolkit"
		date = "2016-09-04"
		score = 80
		hash1 = "24abe9f3f366a3d269f8681be80c99504dea51e50318d83ee42f9a4c7435999a"
	strings:
		$s1 = "Get-ProcAddress kernel32.dll WriteProcessMemory" fullword ascii
		$s2 = "Get-ProcAddress kernel32.dll OpenProcess" fullword ascii
		$s3 = "msfpayload windows/exec CMD=\"cmd /k calc\" EXITFUNC=thread C | sed '1,6d;s/[\";]//g;s/\\\\/,0/g' | tr -d '\\n' | cut -c2- " fullword ascii
		$s4 = "inject shellcode into" ascii
		$s5 = "Injecting shellcode" ascii
	condition:
		( uint16(0) == 0xbbef and filesize < 90KB and 1 of them ) or ( 3 of them )
}