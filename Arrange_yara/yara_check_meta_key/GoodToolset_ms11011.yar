rule GoodToolset_ms11011 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-13"
    description = "Chinese Hacktool Set - file ms11011.exe"
    family = "None"
    hacker = "None"
    hash = "5ad7a4962acbb6b0e3b73d77385eb91feb88b386"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "\\i386\\Hello.pdb" ascii
    $s1 = "OS not supported." fullword ascii
    $s3 = "Not supported." fullword wide  /* Goodware String - occured 3 times */
    $s4 = "SystemDefaultEUDCFont" fullword wide  /* Goodware String - occured 18 times */
  condition:
    uint16(0) == 0x5a4d and filesize < 100KB and all of them
}