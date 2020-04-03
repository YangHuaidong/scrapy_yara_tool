rule FreeVersion_release {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-13"
    description = "Chinese Hacktool Set - file release.exe"
    family = "None"
    hacker = "None"
    hash = "f42e4b5748e92f7a450eb49fc89d6859f4afcebb"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "-->Got WMI process Pid: %d " ascii
    $s2 = "This exploit will execute \"net user " ascii
    $s3 = "net user temp 123456 /add & net localgroup administrators temp /add" fullword ascii
    $s4 = "Running reverse shell" ascii
    $s5 = "wmiprvse.exe" fullword ascii
    $s6 = "SELECT * FROM IIsWebInfo" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 100KB and 3 of them
}