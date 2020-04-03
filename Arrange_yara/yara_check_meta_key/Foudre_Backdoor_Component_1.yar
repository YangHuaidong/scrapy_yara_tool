import "pe"
rule Foudre_Backdoor_Component_1 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-08-01"
    description = "Detects Foudre Backdoor"
    family = "None"
    hacker = "None"
    hash1 = "7c6206eaf0c5c9c6c8d8586a626b49575942572c51458575e51cba72ba2096a4"
    hash2 = "db605d501d3a5ca2b0e3d8296d552fbbf048ee831be21efca407c45bf794b109"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://goo.gl/Nbqbt6"
    threatname = "None"
    threattype = "None"
  strings:
    /* $s1 = "Project1.dll" fullword ascii */
    /* Better: Project1.dll\x00D1 */
    $s1 = { 50 72 6f 6a 65 63 74 31 2e 64 6c 6c 00 44 31 }
    $s2 = "winmgmts:\\\\localhost\\root\\SecurityCenter2" fullword wide
    $s3 = "C:\\Documents and Settings\\All Users\\" fullword wide
  condition:
    ( uint16(0) == 0x5a4d and filesize < 2000KB and
    ( 3 of them ) or
    ( 2 of them and pe.exports("D1") )
}