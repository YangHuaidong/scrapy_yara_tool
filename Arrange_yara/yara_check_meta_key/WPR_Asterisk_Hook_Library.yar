rule WPR_Asterisk_Hook_Library {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-03-15"
    description = "Windows Password Recovery - file ast64.dll"
    family = "None"
    hacker = "None"
    hash1 = "225071140e170a46da0e57ce51f0838f4be00c8f14e9922c6123bee4dffde743"
    hash2 = "95ec84dc709af990073495082d30309c42d175c40bd65cad267e6f103852a02d"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Internal Research"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "ast64.dll" fullword ascii
    $s2 = "ast.dll" fullword wide
    $s3 = "c:\\%s.lvc" fullword ascii
    $s4 = "c:\\%d.lvc" fullword ascii
    $s5 = "Asterisk Hook Library" fullword wide
    $s6 = "?Ast_StartRd64@@YAXXZ" fullword ascii
    $s7 = "Global\\{1374821A-281B-9AF4-%04X-12345678901234}" fullword ascii
    $s8 = "2004-2013 Passcape Software" fullword wide
    $s9 = "Global\\Passcape#6712%04X" fullword ascii
  condition:
    ( uint16(0) == 0x5a4d and filesize < 300KB and 3 of them )
}