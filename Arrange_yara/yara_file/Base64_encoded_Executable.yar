rule Base64_encoded_Executable {
	meta:
		description = "Detects an base64 encoded executable (often embedded)"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		date = "2015-05-28"
		score = 40
		type = "file"
	strings:
		$s1 = "TVpTAQEAAAAEAAAA//8AALgAAAA" // 14 samples in goodware archive
		$s2 = "TVoAAAAAAAAAAAAAAAAAAAAAAAA" // 26 samples in goodware archive
		$s3 = "TVqAAAEAAAAEABAAAAAAAAAAAAA" // 75 samples in goodware archive
		$s4 = "TVpQAAIAAAAEAA8A//8AALgAAAA" // 168 samples in goodware archive
		$s5 = "TVqQAAMAAAAEAAAA//8AALgAAAA" // 28,529 samples in goodware archive
	condition:
		1 of them
		and not filepath contains "Thunderbird"
      and not filepath contains "Internet Explorer"
      and not filepath contains "Chrome"
      and not filepath contains "Opera"
      and not filepath contains "Outlook"
      and not filepath contains "Temporary Internet Files"
}