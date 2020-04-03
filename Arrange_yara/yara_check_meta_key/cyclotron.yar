rule cyclotron {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-13"
    description = "Chinese Hacktool Set - file cyclotron.sys"
    family = "None"
    hacker = "None"
    hash = "5b63473b6dc1e5942bf07c52c31ba28f2702b246"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "\\Device\\IDTProt" fullword wide
    $s2 = "IoDeleteSymbolicLink" fullword ascii  /* Goodware String - occured 467 times */
    $s3 = "\\??\\slIDTProt" fullword wide
    $s4 = "IoDeleteDevice" fullword ascii  /* Goodware String - occured 993 times */
    $s5 = "IoCreateSymbolicLink" fullword ascii /* Goodware String - occured 467 times */
  condition:
    uint16(0) == 0x5a4d and filesize < 3KB and all of them
}