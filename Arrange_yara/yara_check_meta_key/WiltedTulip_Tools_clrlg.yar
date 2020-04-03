rule WiltedTulip_Tools_clrlg {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-07-23"
    description = "Detects Windows eventlog cleaner used in Operation Wilted Tulip - file clrlg.bat"
    family = "None"
    hacker = "None"
    hash1 = "b33fd3420bffa92cadbe90497b3036b5816f2157100bf1d9a3b6c946108148bf"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://www.clearskysec.com/tulip"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "('wevtutil.exe el') DO (call :do_clear" fullword ascii
    $s2 = "wevtutil.exe cl %1" fullword ascii
  condition:
    filesize < 1KB and 1 of them
}