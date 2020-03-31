rule APT_Thrip_Sample_Jun18_15 {
  meta:
    author = Spider
    comment = None
    date = 2018-06-21
    description = Detects sample found in Thrip report by Symantec 
    family = Jun18
    hacker = None
    hash1 = 231c569f11460a12b171f131c40a6f25d8416954b35c28ae184aba8a649d9786
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = https://www.symantec.com/blogs/threat-intelligence/thrip-hits-satellite-telecoms-defense-targets 
    threatname = APT[Thrip]/Sample.Jun18.15
    threattype = Thrip
  strings:
    $s1 = "%s\\cmd.exe /c %s" fullword ascii
    $s2 = "CryptBase.dll" fullword ascii
    $s3 = "gupdate.exe" fullword ascii
    $s4 = "wusa.exe" fullword ascii
    $s5 = "/c %s %s /quiet /extract:%s\\%s\\" fullword ascii
    $s6 = "%s%s.dll.cab" fullword ascii
    $s7 = "%s\\%s\\%s%s %s" fullword ascii
    $s8 = "%s\\%s\\%s%s" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 200KB
    and ( pe.imphash() == "f6ec70a295000ab0a753aa708e9439b4" or 6 of them )
}