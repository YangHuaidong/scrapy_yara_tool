rule APT_Thrip_Sample_Jun18_2 {
  meta:
    author = Spider
    comment = None
    date = 2018-06-21
    description = Detects sample found in Thrip report by Symantec 
    family = Jun18
    hacker = None
    hash1 = 1fc9f7065856cd8dc99b6f46cf0953adf90e2c42a3b65374bf7b50274fb200cc
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = https://www.symantec.com/blogs/threat-intelligence/thrip-hits-satellite-telecoms-defense-targets 
    threatname = APT[Thrip]/Sample.Jun18.2
    threattype = Thrip
  strings:
    $s1 = "C:\\WINDOWS\\system32\\sysprep\\cryptbase.dll" fullword ascii
    $s2 = "ProbeScriptFint" fullword wide
    $s3 = "C:\\WINDOWS\\system32\\cmd.exe" fullword ascii /* Goodware String - occured 2 times */
  condition:
    uint16(0) == 0x5a4d and filesize < 60KB and all of them
}