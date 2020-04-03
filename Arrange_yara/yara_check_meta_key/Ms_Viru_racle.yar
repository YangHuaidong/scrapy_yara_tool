rule Ms_Viru_racle {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-13"
    description = "Chinese Hacktool Set - file racle.dll"
    family = "None"
    hacker = "None"
    hash = "13116078fff5c87b56179c5438f008caf6c98ecb"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "PsInitialSystemProcess @%p" fullword ascii
    $s1 = "PsLookupProcessByProcessId(%u) Failed" fullword ascii
    $s2 = "PsLookupProcessByProcessId(%u) => %p" fullword ascii
    $s3 = "FirstStage() Loaded, CurrentThread @%p Stack %p - %p" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 210KB and all of them
}