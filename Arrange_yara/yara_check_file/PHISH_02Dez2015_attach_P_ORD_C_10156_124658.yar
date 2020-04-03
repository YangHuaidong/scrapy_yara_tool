rule PHISH_02Dez2015_attach_P_ORD_C_10156_124658 {
	meta:
		description = "Phishing Wave - file P-ORD-C-10156-124658.xls"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "http://myonlinesecurity.co.uk/purchase-order-124658-gina-harrowell-clinimed-limited-word-doc-or-excel-xls-spreadsheet-malware/"
		date = "2015-12-02"
		hash1 = "bc252ede5302240c2fef8bc0291ad5a227906b4e70929a737792e935a5fee209"
		hash2 = "e6c5b55586e9d99551adc27a0fc9c080cea6201fae60104b82d5a2ec518fafb6"
		hash3 = "80f278b7268ea6814f8b336e07c5f4b03289519e199fbe4cbd9ef6a38cf25df6"
		hash4 = "3a0a758525883a049a42312e46a023076c31af23b5e8e5b81fec56d51e4c80fb"
		hash5 = "bc252ede5302240c2fef8bc0291ad5a227906b4e70929a737792e935a5fee209"
		hash6 = "d9db7d32949c4df6a5d9d0292b576ae19681be7b6e0684df57338390e87fc6d6"
		hash7 = "7bb705701ae73d377f6091515a140f0af57703719a67da9a60fad4544092ee6c"
		hash8 = "e743c6e7749ab1046a2beea8733d7c8386ea60b43492bb4f0769ced6a2cee66d"
	strings:
		$s1 = "Execute" ascii
		$s2 = "Process WriteParameterFiles" fullword ascii
		$s3 = "WScript.Shell" fullword ascii
		$s4 = "STOCKMASTER" fullword ascii
		$s5 = "InsertEmailFax" ascii
	condition:
		uint16(0) == 0xcfd0 and filesize < 200KB and all of them
}