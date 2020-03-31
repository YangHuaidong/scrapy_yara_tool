rule KiwiTaskmgr_2 {
  meta:
    author = Spider
    comment = None
    date = 2015-06-13
    description = Chinese Hacktool Set - file KiwiTaskmgr.exe
    family = None
    hacker = None
    hash = 8bd6c9f2e8be3e74bd83c6a2d929f8a69422fb16
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = http://tools.zjqhr.com/
    threatname = KiwiTaskmgr[2
    threattype = 2.yar
  strings:
    $s1 = "Process Ok, Memory Ok, resuming process :)" fullword wide
    $s2 = "Kiwi Taskmgr no-gpo" fullword wide
    $s3 = "KiwiAndTaskMgr" fullword wide
  condition:
    uint16(0) == 0x5a4d and filesize < 300KB and all of them
}