rule sbin_squid {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-13"
    description = "Chinese Hacktool Set - file squid.bat"
    family = "None"
    hacker = "None"
    hash = "8b795a8085c3e6f3d764ebcfe6d59e26fdb91969"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "del /s /f /q" fullword ascii
    $s1 = "squid.exe -z" fullword ascii
    $s2 = "net start Squid" fullword ascii
    $s3 = "net stop Squid" fullword ascii
  condition:
    filesize < 1KB and all of them
}