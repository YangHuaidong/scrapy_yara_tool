rule CobaltStrike_Sleep_Decoder_Indicator {
	meta:
		description = "Detects CobaltStrike sleep_mask decoder"
		author = "yara@s3c.za.net"
		date = "2019-08-16"
	strings:
		$sleep_decoder = {8B 07 8B 57 04 83 C7 08 85 C0 75 2C}
	condition:
		$sleep_decoder
}