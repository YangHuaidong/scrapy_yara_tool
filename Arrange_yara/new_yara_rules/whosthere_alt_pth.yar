rule whosthere_alt_pth {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-07-10"
    description = "Auto-generated rule - file pth.dll"
    family = "None"
    hacker = "None"
    hash = "fbfc8e1bc69348721f06e96ff76ae92f3551f33ed3868808efdb670430ae8bd0"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://www.coresecurity.com/corelabs-research/open-source-tools/pass-hash-toolkit"
    score = 80
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "c:\\debug.txt" fullword ascii /* PEStudio Blacklist: strings */ /* score: '23.00' */
    $s1 = "pth.dll" fullword ascii /* score: '20.00' */
    $s2 = "\"Primary\" string found at %.8Xh" fullword ascii /* score: '7.00' */
    $s3 = "\"Primary\" string not found!" fullword ascii /* score: '6.00' */
    $s4 = "segment 1 found at %.8Xh" fullword ascii /* score: '6.00' */
  condition:
    uint16(0) == 0x5a4d and filesize < 240KB and 4 of them
}