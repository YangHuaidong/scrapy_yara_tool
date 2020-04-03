rule jsp_cmd {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-22"
    description = "Laudanum Injector Tools - file cmd.war"
    family = "None"
    hacker = "None"
    hash = "55e4c3dc00cfab7ac16e7cfb53c11b0c01c16d3d"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://laudanum.inguardians.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "cmd.jsp}" fullword ascii
    $s1 = "cmd.jspPK" fullword ascii
    $s2 = "WEB-INF/web.xml" fullword ascii /* Goodware String - occured 1 times */
    $s3 = "WEB-INF/web.xmlPK" fullword ascii /* Goodware String - occured 1 times */
    $s4 = "META-INF/MANIFEST.MF" fullword ascii /* Goodware String - occured 12 times */
  condition:
    uint16(0) == 0x4b50 and filesize < 2KB and all of them
}