rule apt_hellsing_proxytool {
  meta:
    author = "Spider"
    comment = "None"
    copyright = "Kaspersky Lab"
    date = "2015-04-07"
    description = "detection for Hellsing proxy testing tool"
    family = "None"
    filetype = "PE"
    hacker = "None"
    judge = "black"
    reference = "None"
    threatname = "None"
    threattype = "None"
    version = "1.0"
  strings:
    $mz = "MZ"
    $a1 = "PROXY_INFO: automatic proxy url => %s"
    $a2 = "PROXY_INFO: connection type => %d"
    $a3 = "PROXY_INFO: proxy server => %s"
    $a4 = "PROXY_INFO: bypass list => %s"
    $a5 = "InternetQueryOption failed with GetLastError() %d"
    $a6 = "D:\\Hellsing\\release\\exe\\exe\\" nocase
  condition:
    ($mz at 0) and (2 of ($a*)) and filesize < 300000
}