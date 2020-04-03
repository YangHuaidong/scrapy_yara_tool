rule CN_Tools_Temp {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-13"
    description = "Chinese Hacktool Set - file Temp.war"
    family = "None"
    hacker = "None"
    hash = "c3327ef63b0ed64c4906e9940ef877c76ebaff58"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "META-INF/context.xml<?xml version=\"1.0\" encoding=\"UTF-8\"?>" fullword ascii
    $s1 = "browser.jsp" fullword ascii
    $s3 = "cmd.jsp" fullword ascii
    $s4 = "index.jsp" fullword ascii
  condition:
    uint16(0) == 0x4b50 and filesize < 203KB and all of them
}