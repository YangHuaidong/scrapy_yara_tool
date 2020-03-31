rule PasswordPro_NTLM_DLL {
   meta:
      description = "Auto-generated rule - file NTLM.dll"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "PasswordPro"
      date = "2017-08-27"
      hash1 = "47d4755d31bb96147e6230d8ea1ecc3065da8e557e8176435ccbcaea16fe50de"
   strings:
      $s1 = "NTLM.dll" fullword ascii
      $s2 = "Algorithm: NTLM" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and
        filesize < 20KB and
        pe.exports("GetHash") and pe.exports("GetInfo") and
        ( all of them )
      )
}