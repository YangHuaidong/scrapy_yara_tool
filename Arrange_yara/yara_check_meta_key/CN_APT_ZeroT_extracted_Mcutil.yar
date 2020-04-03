rule CN_APT_ZeroT_extracted_Mcutil {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-02-04"
    description = "Chinese APT by Proofpoint ZeroT RAT  - file Mcutil.dll"
    family = "None"
    hacker = "None"
    hash1 = "266c06b06abbed846ebabfc0e683f5d20dadab52241bc166b9d60e9b8493b500"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://www.proofpoint.com/us/threat-insight/post/APT-targets-russia-belarus-zerot-plugx"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "LoaderDll.dll" fullword ascii
    $s2 = "QageBox1USER" fullword ascii
    $s3 = "xhmowl" fullword ascii
    $s4 = "?KEYKY" fullword ascii
    $s5 = "HH:mm:_s" fullword ascii
    $s6 = "=licni] has maX0t" fullword ascii
  condition:
    ( uint16(0) == 0x5a4d and filesize < 90KB and 3 of them ) or ( all of them )
}