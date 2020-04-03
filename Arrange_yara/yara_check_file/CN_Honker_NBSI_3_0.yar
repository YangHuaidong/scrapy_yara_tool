rule CN_Honker_NBSI_3_0 {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file NBSI 3.0.exe"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "93bf0f64bec926e9aa2caf4c28df9af27ec0e104"
	strings:
		$s1 = ";use master declare @o int exec sp_oacreate 'wscript.shell',@o out exec sp_oamet" wide /* PEStudio Blacklist: strings */
		$s2 = "http://localhost/1.asp?id=16" fullword ascii /* PEStudio Blacklist: strings */
		$s3 = " exec master.dbo.xp_cmdshell @Z--" fullword wide /* PEStudio Blacklist: strings */
		$s4 = ";use master declare @o int exec sp_oacreate 'wscript.shell',@o out exec sp_oamet" wide /* PEStudio Blacklist: strings */
	condition:
		uint16(0) == 0x5a4d and filesize < 2600KB and 2 of them
}