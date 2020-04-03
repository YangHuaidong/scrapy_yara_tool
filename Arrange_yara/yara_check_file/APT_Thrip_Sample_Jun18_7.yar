rule APT_Thrip_Sample_Jun18_7 {
   meta:
      description = "Detects sample found in Thrip report by Symantec "
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.symantec.com/blogs/threat-intelligence/thrip-hits-satellite-telecoms-defense-targets "
      date = "2018-06-21"
      hash1 = "6b714dc1c7e58589374200d2c7f3d820798473faeb26855e53101b8f3c701e3f"
   strings:
      $s1 = "C:\\runme.exe" ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 60KB and 1 of them
}