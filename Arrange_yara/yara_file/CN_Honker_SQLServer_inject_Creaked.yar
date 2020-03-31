rule CN_Honker_SQLServer_inject_Creaked {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file SQLServer_inject_Creaked.exe"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "af3c41756ec8768483a4cf59b2e639994426e2c2"
	strings:
		$s1 = "http://localhost/index.asp?id=2" fullword ascii /* PEStudio Blacklist: strings */
		$s2 = "Email:zhaoxypass@yahoo.com.cn<br>" fullword ascii /* PEStudio Blacklist: strings */
	condition:
		uint16(0) == 0x5a4d and filesize < 8110KB and all of them
}