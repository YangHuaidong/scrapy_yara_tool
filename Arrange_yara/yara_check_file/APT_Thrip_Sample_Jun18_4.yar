rule APT_Thrip_Sample_Jun18_4 {
   meta:
      description = "Detects sample found in Thrip report by Symantec "
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.symantec.com/blogs/threat-intelligence/thrip-hits-satellite-telecoms-defense-targets "
      date = "2018-06-21"
      hash1 = "6b236d3fc54d36e6dc2a26299f6ded597058fed7c9099f1a37716c5e4b162abc"
   strings:
      $s1 = "\\system32\\wbem\\tmf\\caches_version.db" fullword ascii
      $s2 = "ProcessName No Access" fullword ascii
      $s3 = "Hwnd of Process NULL" fullword ascii
      $s4 = "*********The new session is be opening:(%d)**********" fullword ascii
      $s5 = "[EXECUTE]" fullword ascii
      $s6 = "/------------------------------------------------------------------------" fullword ascii
      $s7 = "constructor or from DllMain." fullword ascii
      $s8 = "Time:%d-%d-%d %d:%d:%d" fullword ascii
      $s9 = "\\info.config" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and 5 of them
}