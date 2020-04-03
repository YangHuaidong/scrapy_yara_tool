rule CN_Honker_sig_3389_mstsc_MSTSCAX {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file MSTSCAX.DLL"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "2fa006158b2d87b08f1778f032ab1b8e139e02c6"
	strings:
		$s1 = "ResetPasswordWWWx" fullword ascii /* PEStudio Blacklist: strings */
		$s2 = "Terminal Server Redirected Printer Doc" fullword wide /* PEStudio Blacklist: strings */
		$s3 = "Cleaning temp directory" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 1000KB and all of them
}