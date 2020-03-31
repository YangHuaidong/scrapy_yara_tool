rule _Project1_Generate_rejoice {
  meta:
    author = Spider
    comment = None
    date = 2015-06-13
    description = Chinese Hacktool Set - from files Project1.exe, Generate.exe, rejoice.exe
    family = rejoice
    hacker = None
    hash0 = d1a5e3b646a16a7fcccf03759bd0f96480111c96
    hash1 = 2cb4c3916271868c30c7b4598da697f59e9c7a12
    hash2 = fe634a9f5d48d5c64c8f8bfd59ac7d8965d8f372
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = http://tools.zjqhr.com/
    super_rule = 1
    threatname = [Project1]/Generate.rejoice
    threattype = Project1
  strings:
    $s1 = "sfUserAppDataRoaming" fullword ascii
    $s2 = "$TRzFrameControllerPropertyConnection" fullword ascii
    $s3 = "delphi32.exe" fullword ascii
    $s4 = "hkeyCurrentUser" fullword ascii
    $s5 = "%s is not a valid IP address." fullword wide
    $s6 = "Citadel hooking error" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 2000KB and all of them
}