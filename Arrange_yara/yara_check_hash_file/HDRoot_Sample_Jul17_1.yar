rule HDRoot_Sample_Jul17_1 {
  meta:
    author = Spider
    comment = None
    date = 2017-07-07
    description = Detects HDRoot samples
    family = 1
    hacker = None
    hash1 = 6d2ad82f455becc8c830d000633a370857928c584246a7f41fe722cc46c0d113
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = Winnti HDRoot VT
    threatname = HDRoot[Sample]/Jul17.1
    threattype = Sample
  strings:
    $s1 = "gleupdate.dll" fullword ascii
    $s2 = "\\DosDevices\\%ws\\system32\\%ws" fullword wide
    $s3 = "l\\Driver\\nsiproxy" fullword wide
  condition:
    ( uint16(0) == 0x5a4d and filesize < 60KB and 3 of them )
}