rule HScan_v1_20_PipeCmd {
  meta:
    author = Spider
    comment = None
    date = 2015-06-13
    description = Chinese Hacktool Set - file PipeCmd.exe
    family = PipeCmd
    hacker = None
    hash = 64403ce63b28b544646a30da3be2f395788542d6
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = http://tools.zjqhr.com/
    threatname = HScan[v1]/20.PipeCmd
    threattype = v1
  strings:
    $s1 = "%SystemRoot%\\system32\\PipeCmdSrv.exe" fullword ascii
    $s2 = "PipeCmd.exe" fullword wide
    $s3 = "Please Use NTCmd.exe Run This Program." fullword ascii
    $s4 = "%s\\pipe\\%s%s%d" fullword ascii
    $s5 = "\\\\.\\pipe\\%s%s%d" fullword ascii
    $s6 = "%s\\ADMIN$\\System32\\%s%s" fullword ascii
    $s7 = "This is a service executable! Couldn't start directly." fullword ascii
    $s8 = "Connecting to Remote Server ...Failed" fullword ascii
    $s9 = "PIPECMDSRV" fullword wide
  condition:
    uint16(0) == 0x5a4d and filesize < 200KB and 4 of them
}