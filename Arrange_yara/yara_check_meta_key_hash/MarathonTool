rule MarathonTool {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-13"
    description = "Chinese Hacktool Set - file MarathonTool.exe"
    family = "None"
    hacker = "None"
    hash = "084a27cd3404554cc799d0e689f65880e10b59e3"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "MarathonTool" ascii
    $s17 = "/Blind SQL injection tool based in heavy queries" fullword ascii
    $s18 = "SELECT UNICODE(SUBSTRING((system_user),{0},1))" fullword wide
  condition:
    uint16(0) == 0x5a4d and filesize < 1040KB and all of them
}