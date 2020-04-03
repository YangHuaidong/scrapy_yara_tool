rule IsDebug_V1_4 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-13"
    description = "Chinese Hacktool Set - file IsDebug V1.4.dll"
    family = "None"
    hacker = "None"
    hash = "ca32474c358b4402421ece1cb31714fbb088b69a"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "IsDebug.dll" fullword ascii
    $s1 = "SV Dumper V1.0" fullword wide
    $s2 = "(IsDebuggerPresent byte Patcher)" fullword ascii
    $s8 = "Error WriteMemory failed" fullword ascii
    $s9 = "IsDebugPresent" fullword ascii
    $s10 = "idb_Autoload" fullword ascii
    $s11 = "Bin Files" fullword ascii
    $s12 = "MASM32 version" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 30KB and all of them
}