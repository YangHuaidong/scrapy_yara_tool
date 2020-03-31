rule dll_Reg {
  meta:
    author = Spider
    comment = None
    date = 2015-06-13
    description = Chinese Hacktool Set - file Reg.bat
    family = None
    hacker = None
    hash = cb8a92fe256a3e5b869f9564ecd1aa9c5c886e3f
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = http://tools.zjqhr.com/
    threatname = dll[Reg
    threattype = Reg.yar
  strings:
    $s0 = "copy PacketX.dll C:\\windows\\system32\\PacketX.dll" fullword ascii
    $s1 = "regsvr32.exe C:\\windows\\system32\\PacketX.dll" fullword ascii
  condition:
    filesize < 1KB and all of them
}