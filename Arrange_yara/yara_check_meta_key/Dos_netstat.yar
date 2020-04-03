rule Dos_netstat {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-13"
    description = "Chinese Hacktool Set - file netstat.exe"
    family = "None"
    hacker = "None"
    hash = "d0444b7bd936b5fc490b865a604e97c22d97e598"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "w03a2409.dll" fullword ascii
    $s1 = "Retransmission Timeout Algorithm    = unknown (%1!u!)" fullword wide  /* Goodware String - occured 2 times */
    $s2 = "Administrative Status  = %1!u!" fullword wide  /* Goodware String - occured 2 times */
    $s3 = "Packet Too Big            %1!-10u!  %2!-10u!" fullword wide  /* Goodware String - occured 2 times */
  condition:
    uint16(0) == 0x5a4d and filesize < 150KB and all of them
}