import "pe"

rule WiltedTulip_matryoshka_Injector {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-07-23"
    description = "Detects hack tool used in Operation Wilted Tulip"
    family = "None"
    hacker = "None"
    hash1 = "c41e97b3b22a3f0264f10af2e71e3db44e53c6633d0d690ac4d2f8f5005708ed"
    hash2 = "b93b5d6716a4f8eee450d9f374d0294d1800784bc99c6934246570e4baffe509"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://www.clearskysec.com/tulip"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "Injector.dll" fullword ascii
    $s2 = "ReflectiveLoader" fullword ascii
  condition:
    ( uint16(0) == 0x5a4d and filesize < 1000KB and all of them ) or
    pe.exports("__dec") and
    pe.exports("_check") and
    pe.exports("_dec") and
    pe.exports("start") and
    pe.exports("test")
}