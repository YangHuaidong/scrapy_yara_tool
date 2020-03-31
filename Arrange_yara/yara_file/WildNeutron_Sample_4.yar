rule WildNeutron_Sample_4 {
	meta:
		description = "Wild Neutron APT Sample Rule - file b4005530193bc523d3e0193c3c53e2737ae3bf9f76d12c827c0b5cd0dcbaae45"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://securelist.com/blog/research/71275/wild-neutron-economic-espionage-threat-actor-returns-with-new-tricks/"
		date = "2015-07-10"
		score = 60
		hash = "b4005530193bc523d3e0193c3c53e2737ae3bf9f76d12c827c0b5cd0dcbaae45"
	strings:
		$x1 = "WinRAT-Win32-Release.exe" fullword ascii /* score: '22.00' */
		$s0 = "rundll32.exe \"%s\",#1" fullword wide /* PEStudio Blacklist: strings */ /* score: '33.00' */
		$s1 = "RtlUpd.EXE" fullword wide /* score: '20.00' */
		$s2 = "RtlUpd.exe" fullword wide /* score: '20.00' */
		$s3 = "Driver Update and remove for Windows x64 or x86_32" fullword wide /* PEStudio Blacklist: strings */ /* score: '17.00' */
		$s4 = "Realtek HD Audio Update and remove driver Tool" fullword wide /* PEStudio Blacklist: strings */ /* score: '16.00' */
		$s5 = "%s%s%s=%d,%s=%d,%s=%d," fullword wide /* score: '15.00' */
		$s6 = "Key Usage" fullword ascii /* score: '12.00' */
		$s7 = "id-at-serialNumber" fullword ascii /* PEStudio Blacklist: strings */ /* score: '10.00' */
	condition:
		uint16(0) == 0x5a4d and filesize < 1240KB and all of them
}