rule EquationGroup_GetAdmin_Lp {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-01-13"
    description = "EquationGroup Malware - file GetAdmin_Lp.dll"
    family = "None"
    hacker = "None"
    hash1 = "e1c9c9f031d902e69e42f684ae5b35a2513f7d5f8bca83dfbab10e8de6254c78"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://goo.gl/tcSoiJ"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "Current user is System -- unable to join administrators group" fullword wide
  condition:
    ( uint16(0) == 0x5a4d and filesize < 300KB and all of them )
}