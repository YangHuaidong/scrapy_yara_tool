rule APT30_Sample_30 {
	meta:
		description = "FireEye APT30 Report Sample - file bf8616bbed6d804a3dea09b230c2ab0c"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash = "3b684fa40b4f096e99fbf535962c7da5cf0b4528"
	strings:
		$s0 = "5.1.2600.2180 (xpsp_sp2_rtm.040803-2158)" fullword wide
		$s3 = "RnhwtxtkyLRRMf{jJ}ny" fullword ascii
		$s4 = "RnhwtxtkyLRRJ}ny" fullword ascii
		$s5 = "ZRLDownloadToFileA" fullword ascii
		$s9 = "5.1.2600.2180" fullword wide
	condition:
		filesize < 100KB and uint16(0) == 0x5A4D and all of them
}