rule WSOShell_0bbebaf46f87718caba581163d4beed56ddf73a7 {
	meta:
		description = "Detects a web shell"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://github.com/bartblaze/PHP-backdoors"
		date = "2016-09-10"
		hash1 = "d053086907aed21fbb6019bf9e644d2bae61c63563c4c3b948d755db3e78f395"
	strings:
		$s8 = "$default_charset='Wi'.'ndo.'.'ws-12'.'51';" fullword ascii
		$s9 = "$mosimage_session = \"" fullword ascii
	condition:
		( uint16(0) == 0x3f3c and filesize < 300KB and all of them )
}