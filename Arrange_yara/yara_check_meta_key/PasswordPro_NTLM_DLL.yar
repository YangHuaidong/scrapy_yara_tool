import "pe"
rule PasswordPro_NTLM_DLL {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-08-27"
    description = "Auto-generated rule - file NTLM.dll"
    family = "None"
    hacker = "None"
    hash1 = "47d4755d31bb96147e6230d8ea1ecc3065da8e557e8176435ccbcaea16fe50de"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "PasswordPro"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "NTLM.dll" fullword ascii
    $s2 = "Algorithm: NTLM" fullword ascii
  condition:
    ( uint16(0) == 0x5a4d and
    filesize < 20KB and
    pe.exports("GetHash") and pe.exports("GetInfo") and
    ( all of them )
}