rule Webshell_FOPO_Obfuscation_APT_ON_Nov17_1 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-11-17"
    description = "Detects malware from NK APT incident DE"
    family = "None"
    hacker = "None"
    hash1 = "ed6e2e0027d3f564f5ce438984dc8a54577df822ce56ce079c60c99a91d5ffb1"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Internal Research - ON"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "Obfuscation provided by FOPO" fullword ascii
    $s1 = "\";@eval($" ascii
    $f1 = { 22 29 29 3b 0d 0a 3f 3e }
  condition:
    uint16(0) == 0x3f3c and filesize < 800KB and (
    $x1 or
    ( $s1 in (0..350) and $f1 at (filesize-23) )
}