rule CN_Honker__PostgreSQL_mysql_injectV1_1_Creak_Oracle_SQLServer_inject_Creaked {
	meta:
		description = "Sample from CN Honker Pentest Toolset"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		super_rule = 1
		hash0 = "1ecfaa91aae579cfccb8b7a8607176c82ec726f4"
		hash1 = "a1f066789f48a76023598c5777752c15f91b76b0"
		hash2 = "0264f4efdba09eaf1e681220ba96de8498ab3580"
		hash3 = "af3c41756ec8768483a4cf59b2e639994426e2c2"
	strings:
		$s1 = "zhaoxypass@yahoo.com.cn" fullword ascii /* PEStudio Blacklist: strings */
		$s2 = "Mozilla/3.0 (compatible; Indy Library)" fullword ascii /* PEStudio Blacklist: strings */
		$s3 = "ProxyParams.ProxyPort" fullword ascii /* PEStudio Blacklist: strings */
	condition:
		uint16(0) == 0x5a4d and all of them
}