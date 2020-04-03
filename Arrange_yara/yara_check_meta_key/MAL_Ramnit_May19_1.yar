import "pe"
rule MAL_Ramnit_May19_1 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2019-05-31"
    description = "Detects Ramnit malware"
    family = "None"
    hacker = "None"
    hash1 = "d7ec3fcd80b3961e5bab97015c91c843803bb915c13a4a35dfb5e9bdf556c6d3"
    judge = "black"
    reference = "https://www.guardicore.com/2019/05/nansh0u-campaign-hackers-arsenal-grows-stronger/"
    threatname = "None"
    threattype = "None"
  condition:
    uint16(0) == 0x5a4d and filesize < 300KB
    and pe.imphash() == "500cd02578808f964519eb2c85153046"
}