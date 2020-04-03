rule Base64_encoded_Executable {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-05-28"
    description = "Detects an base64 encoded executable (often embedded)"
    family = "None"
    hacker = "None"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 40
    threatname = "None"
    threattype = "None"
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