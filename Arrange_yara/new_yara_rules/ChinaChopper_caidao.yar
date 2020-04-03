rule ChinaChopper_caidao {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-13"
    description = "Chinese Hacktool Set - file caidao.exe"
    family = "None"
    hacker = "None"
    hash = "056a60ec1f6a8959bfc43254d97527b003ae5edb"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "Pass,Config,n{)" fullword ascii
    $s2 = "phMYSQLZ" fullword ascii
    $s3 = "\\DHLP\\." fullword ascii
    $s4 = "\\dhlp\\." fullword ascii
    $s5 = "SHAutoComple" fullword ascii
    $s6 = "MainFrame" ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 1077KB and all of them
}