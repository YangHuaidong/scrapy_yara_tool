rule f3_diy {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-13"
    description = "Chinese Hacktool Set - file diy.asp"
    family = "None"
    hacker = "None"
    hash = "f39c2f64abe5e86d8d36dbb7b1921c7eab63bec9"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "<%@LANGUAGE=\"VBScript.Encode\" CODEPAGE=\"936\"%>" fullword ascii
    $s5 = ".black {" fullword ascii
  condition:
    uint16(0) == 0x253c and filesize < 10KB and all of them
}