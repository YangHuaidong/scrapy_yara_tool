rule Ms_Viru_v {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-13"
    description = "Chinese Hacktool Set - file v.exe"
    family = "None"
    hacker = "None"
    hash = "ecf4ba6d1344f2f3114d52859addee8b0770ed0d"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "c:\\windows\\system32\\command.com /c " fullword ascii
    $s2 = "Easy Usage Version -- Edited By: racle@tian6.com" fullword ascii
    $s3 = "OH,Sry.Too long command." fullword ascii
    $s4 = "Success! Commander." fullword ascii
    $s5 = "Hey,how can racle work without ur command ?" fullword ascii
    $s6 = "The exploit thread was unable to map the virtual 8086 address space" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 100KB and 3 of them
}