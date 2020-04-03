rule CN_Tools_MyUPnP {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-13"
    description = "Chinese Hacktool Set - file MyUPnP.exe"
    family = "None"
    hacker = "None"
    hash = "15b6fca7e42cd2800ba82c739552e7ffee967000"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "<description>BYTELINKER.COM</description>" fullword ascii
    $s2 = "myupnp.exe" fullword ascii
    $s3 = "LOADER ERROR" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 1500KB and all of them
}