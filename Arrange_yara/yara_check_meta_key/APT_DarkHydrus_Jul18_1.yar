import "pe"
rule APT_DarkHydrus_Jul18_1 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-07-28"
    description = "Detects strings found in malware samples in APT report in DarkHydrus"
    family = "None"
    hacker = "None"
    hash1 = "99541ab28fc3328e25723607df4b0d9ea0a1af31b58e2da07eff9f15c4e6565c"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://researchcenter.paloaltonetworks.com/2018/07/unit42-new-threat-actor-group-darkhydrus-targets-middle-east-government/"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "Z:\\devcenter\\aggressor\\" ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 600KB and (
    pe.imphash() == "d3666d1cde4790b22b44ec35976687fb" or
    1 of them
}