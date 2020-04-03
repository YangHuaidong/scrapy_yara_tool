rule CobaltStrike_C2_Host_Indicator {
	meta:
		description = "Detects CobaltStrike C2 host artifacts"
		author = "yara@s3c.za.net"
		date = "2019-08-16"
	strings:
		$c2_indicator_fp = "#Host: %s"
		$c2_indicator = "#Host:"
	condition:
		$c2_indicator and not $c2_indicator_fp
		and not uint32(0) == 0x0a786564
		and not uint32(0) == 0x0a796564
}