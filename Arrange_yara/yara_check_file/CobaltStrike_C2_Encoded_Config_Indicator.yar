rule CobaltStrike_C2_Encoded_Config_Indicator {
	meta:
		description = "Detects CobaltStrike C2 encoded profile configuration"
		author = "yara@s3c.za.net"
		date = "2019-08-16"
	strings:
		$c2_enc_config = {69 68 69 68 69 6B ?? ?? 69 6B 69 68 69 6B ?? ?? 69 6A 69 6B 69 6D ?? ?? ?? ?? 69 6D 69 6B 69 6D ?? ?? ?? ?? 69 6C 69 68 69 6B ?? ?? 69 6F 69 68 69 6B ?? ?? 69 6E 69 6A 68 69}
	condition:
		$c2_enc_config
}