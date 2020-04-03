rule QQBrowser {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-06-02"
    description = "Not malware but suspicious browser - file QQBrowser.exe"
    family = "None"
    hacker = "None"
    hash1 = "adcf6b8aa633286cd3a2ce7c79befab207802dec0e705ed3c74c043dabfc604c"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://goo.gl/4pTkGQ"
    score = 50
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "TerminateProcessWithoutDump" fullword ascii
    $s2 = ".Downloader.dll" fullword wide
    $s3 = "Software\\Chromium\\BrowserCrashDumpAttempts" fullword wide
    $s4 = "QQBrowser_Broker.exe" fullword wide
  condition:
    ( uint16(0) == 0x5a4d and filesize < 2000KB and all of them )
}