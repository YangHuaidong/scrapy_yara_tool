rule CN_Honker_LogCleaner {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file LogCleaner.exe"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "ab77ed5804b0394d58717c5f844d9c0da5a9f03e"
	strings:
		$s3 = ".exe <ip> [(path]" fullword ascii
		$s4 = "LogCleaner v" ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 250KB and all of them
}