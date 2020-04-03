rule Malicious_BAT_Strings {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-01-05"
    description = "Detects a string also used in Netwire RAT auxilliary"
    family = "None"
    hacker = "None"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://pastebin.com/8qaiyPxs"
    score = 60
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "call :deleteSelf&exit /b"
  condition:
    filesize < 600KB and 1 of them
}