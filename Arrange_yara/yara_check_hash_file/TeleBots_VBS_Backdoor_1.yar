rule TeleBots_VBS_Backdoor_1 {
  meta:
    author = Spider
    comment = None
    date = 2016-12-14
    description = Detects TeleBots malware - VBS Backdoor
    family = 1
    hacker = None
    hash1 = eb31a918ccc1643d069cf08b7958e2760e8551ba3b88ea9e5d496e07437273b2
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = https://goo.gl/4if3HG
    threatname = TeleBots[VBS]/Backdoor.1
    threattype = VBS
  strings:
    $s1 = "cmd = \"cmd.exe /c \" + arg + \" >\" + outfile +\" 2>&1\"" fullword ascii
    $s2 = "GetTemp = \"c:\\WINDOWS\\addins\"" fullword ascii
    $s3 = "elseif (arg0 = \"-dump\") Then" fullword ascii
    $s4 = "decode = \"certutil -decode \" + source + \" \" + dest  " fullword ascii
  condition:
    ( uint16(0) == 0x6553 and filesize < 8KB and 1 of them ) or ( all of them )
}