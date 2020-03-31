rule IDTools_For_WinXP_IdtTool_2 {
  meta:
    author = Spider
    comment = None
    date = 2015-06-13
    description = Chinese Hacktool Set - file IdtTool.sys
    family = IdtTool
    hacker = None
    hash = 07feb31dd21d6f97614118b8a0adf231f8541a67
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = http://tools.zjqhr.com/
    threatname = IDTools[For]/WinXP.IdtTool.2
    threattype = For
  strings:
    $s0 = "\\Device\\devIdtTool" fullword wide
    $s1 = "IoDeleteSymbolicLink" fullword ascii  /* Goodware String - occured 467 times */
    $s3 = "IoDeleteDevice" fullword ascii  /* Goodware String - occured 993 times */
    $s6 = "IoCreateSymbolicLink" fullword ascii /* Goodware String - occured 467 times */
    $s7 = "IoCreateDevice" fullword ascii /* Goodware String - occured 988 times */
  condition:
    uint16(0) == 0x5a4d and filesize < 7KB and all of them
}