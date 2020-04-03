rule pw_inspector {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-13"
    description = "Chinese Hacktool Set - file pw-inspector.exe"
    family = "None"
    hacker = "None"
    hash = "4f8e3e101098fc3da65ed06117b3cb73c0a66215"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "-m MINLEN  minimum length of a valid password" fullword ascii
    $s2 = "http://www.thc.org" fullword ascii
    $s3 = "Use for hacking: trim your dictionary file to the pw requirements of the target." fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 460KB and all of them
}