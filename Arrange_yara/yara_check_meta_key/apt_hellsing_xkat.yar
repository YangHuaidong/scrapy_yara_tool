rule apt_hellsing_xkat {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-04-07"
    description = "detection for Hellsing xKat tool"
    family = "None"
    filetype = "PE"
    hacker = "None"
    judge = "black"
    reference = "None"
    threatname = "None"
    threattype = "None"
    version = "1.0"
  strings:
    $mz = "MZ"
    $a1 = "\\Dbgv.sys" $a2="XKAT_BIN" $a3="release sys file error."
    $a4 = "driver_load error. "
    $a5 = "driver_create error."
    $a6 = "delete file:%s error."
    $a7 = "delete file:%s ok."
    $a8 = "kill pid:%d error."
    $a9 = "kill pid:%d ok."
    $a10 = "-pid-delete"
    $a11 = "kill and delete pid:%d error."
    $a12 = "kill and delete pid:%d ok."
  condition:
    ($mz at 0) and (6 of ($a*)) and filesize < 300000
}