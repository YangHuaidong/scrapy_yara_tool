rule APT_Thrip_Sample_Jun18_3 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-06-21"
    description = "Detects sample found in Thrip report by Symantec "
    family = "None"
    hacker = "None"
    hash1 = "0d2abdcaad99e102fdf6574b3dc90f17cb9d060c20e6ac4ff378875d3b91a840"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://www.symantec.com/blogs/threat-intelligence/thrip-hits-satellite-telecoms-defense-targets "
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "C:\\Windows\\SysNative\\cmd.exe" fullword ascii
    $s2 = "C:\\Windows\\SysNative\\sysprep\\cryptbase.dll" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 60KB and all of them
}