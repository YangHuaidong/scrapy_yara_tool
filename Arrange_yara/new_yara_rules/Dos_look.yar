rule Dos_look {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-13"
    description = "Chinese Hacktool Set - file look.exe"
    family = "None"
    hacker = "None"
    hash = "e1a37f31170e812185cf00a838835ee59b8f64ba"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "<description>CHKen QQ:41901298</description>" fullword ascii
    $s2 = "version=\"9.9.9.9\"" fullword ascii
    $s3 = "name=\"CH.Ken.Tool\"" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 40KB and all of them
}