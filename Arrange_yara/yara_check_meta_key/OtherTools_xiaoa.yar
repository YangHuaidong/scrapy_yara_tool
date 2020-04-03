rule OtherTools_xiaoa {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-13"
    description = "Chinese Hacktool Set - file xiaoa.exe"
    family = "None"
    hacker = "None"
    hash = "6988acb738e78d582e3614f83993628cf92ae26d"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "Usage:system_exp.exe \"cmd\"" fullword ascii
    $s2 = "The shell \"cmd\" success!" fullword ascii
    $s3 = "Not Windows NT family OS." fullword ascii /* PEStudio Blacklist: os */
    $s4 = "Unable to get kernel base address." fullword ascii
    $s5 = "run \"%s\" failed,code: %d" fullword ascii
    $s6 = "Windows Kernel Local Privilege Exploit " fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 100KB and 2 of them
}