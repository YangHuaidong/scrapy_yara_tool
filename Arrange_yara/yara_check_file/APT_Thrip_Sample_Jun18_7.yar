rule APT_Thrip_Sample_Jun18_7 {
  meta:
    author = Spider
    comment = None
    date = 2018-06-21
    description = Detects sample found in Thrip report by Symantec 
    family = Jun18
    hacker = None
    hash1 = 6b714dc1c7e58589374200d2c7f3d820798473faeb26855e53101b8f3c701e3f
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = https://www.symantec.com/blogs/threat-intelligence/thrip-hits-satellite-telecoms-defense-targets 
    threatname = APT[Thrip]/Sample.Jun18.7
    threattype = Thrip
  strings:
    $s1 = "C:\\runme.exe" ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 60KB and 1 of them
}