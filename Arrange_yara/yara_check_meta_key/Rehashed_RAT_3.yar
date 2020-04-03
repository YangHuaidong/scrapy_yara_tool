rule Rehashed_RAT_3 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-09-08"
    description = "Detects malware from Rehashed RAT incident"
    family = "None"
    hacker = "None"
    hash1 = "9cebae97a067cd7c2be50d7fd8afe5e9cf935c11914a1ab5ff59e91c1e7e5fc4"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://blog.fortinet.com/2017/09/05/rehashed-rat-used-in-apt-campaign-against-vietnamese-organizations"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "\\BisonNewHNStubDll\\Release\\Goopdate.pdb" fullword ascii
    $s2 = "psisrndrx.ebd" fullword wide
    $s3 = "pbad exception" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 100KB and ( 1 of ($x*) or 2 of them )
}