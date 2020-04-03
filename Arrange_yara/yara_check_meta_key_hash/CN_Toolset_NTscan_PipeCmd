rule CN_Toolset_NTscan_PipeCmd {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015/03/30"
    description = "Detects a Chinese hacktool from a disclosed toolset - file PipeCmd.exe"
    family = "None"
    hacker = "None"
    hash = "a931d65de66e1468fe2362f7f2e0ee546f225c4e"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://qiannao.com/ls/905300366/33834c0c/"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s2 = "Please Use NTCmd.exe Run This Program." fullword ascii
    $s3 = "PipeCmd.exe" fullword wide
    $s4 = "\\\\.\\pipe\\%s%s%d" fullword ascii
    $s5 = "%s\\pipe\\%s%s%d" fullword ascii
    $s6 = "%s\\ADMIN$\\System32\\%s%s" fullword ascii
    $s7 = "%s\\ADMIN$\\System32\\%s" fullword ascii
    $s9 = "PipeCmdSrv.exe" fullword ascii
    $s10 = "This is a service executable! Couldn't start directly." fullword ascii
    $s13 = "\\\\.\\pipe\\PipeCmd_communicaton" fullword ascii
    $s14 = "PIPECMDSRV" fullword wide
    $s15 = "PipeCmd Service" fullword ascii
  condition:
    4 of them
}