rule f3_diy {
    meta:
        description = "Chinese Hacktool Set - file diy.asp"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "f39c2f64abe5e86d8d36dbb7b1921c7eab63bec9"
    strings:
        $s0 = "<%@LANGUAGE=\"VBScript.Encode\" CODEPAGE=\"936\"%>" fullword ascii
        $s5 = ".black {" fullword ascii
    condition:
        uint16(0) == 0x253c and filesize < 10KB and all of them
}