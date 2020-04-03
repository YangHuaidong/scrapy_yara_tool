rule APT_FIN7_Sample_Aug18_1 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-08-01"
    description = "Detects FIN7 samples mentioned in FireEye report"
    family = "None"
    hacker = "None"
    hash1 = "a1e95ac1bb684186e9fb5c67f75c7c26ddc8b18ebfdaf061742ddf1675e17d55"
    hash2 = "dc645aae5d283fa175cf463a19615ed4d16b1d5238686245574d8a6a8b0fc8fa"
    hash3 = "eebbce171dab636c5ac0bf0fd14da0e216758b19c0ce2e5c572d7e6642d36d3d"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "\\par var console=\\{\\};console.log=function()\\{\\};" fullword ascii
    $s2 = "616e64792d7063" ascii /* hex encoded string 'andy-pc' */
    $x1 = "0043003a005c00550073006500720073005c0061006e00640079005c004400650073006b0074006f0070005c0075006e00700072006f0074006500630074" ascii /* hex encoded string 'C:\Users\andy\Desktop\unprotect' */
    $x2 = "780065006300750074006500280022004f006e0020004500720072006f007200200052006500730075006d00650020004e006500780074003a0073006500" ascii /* hex encoded string 'xecute("On Error Resume Next:se' */
    $x3 = "\\par \\tab \\tab \\tab sh.Run \"powershell.exe -NoE -NoP -NonI -ExecutionPolicy Bypass -w Hidden -File \" & pToPSCb, 0, False" fullword ascii
    $x4 = "002e006c006e006b002d00000043003a005c00550073006500720073005c007400650073007400610064006d0069006e002e0054004500530054005c0044" ascii /* hex encoded string '.lnk-C:\Users\testadmin.TEST\D' */
    $x5 = "005c00550073006500720073005c005400450053005400410044007e0031002e005400450053005c0041007000700044006100740061005c004c006f0063" ascii /* hex encoded string '\Users\TESTAD~1.TES\AppData\Loc' */
    $x6 = "6c00690063006100740069006f006e002200220029003a00650078006500630075007400650020007700700072006f0074006500630074002e0041006300" ascii /* hex encoded string 'lication""):execute wprotect.Ac' */
    $x7 = "7374656d33325c6d736874612e657865000023002e002e005c002e002e005c002e002e005c00570069006e0064006f00770073005c005300790073007400" ascii /* hex encoded string 'stem32\mshta.exe#..\..\..\Windows\Syst' */
    $x8 = "\\par \\tab \\tab sh.Run \"%comspec% /c tasklist >\"\"\" & tpath & \"\"\" 2>&1\", 0, true" fullword ascii
    $x9 = "00720079007b006500760061006c0028002700770061006c006c003d004700650074004f0062006a0065006300740028005c005c0027005c005c00270027" ascii /* hex encoded string 'ry{eval('wall=GetObject(\\'\\''' */
    $x10 = "006e00640079005c004400650073006b0074006f0070005c0075006e006c006f0063006b002e0064006f0063002e006c006e006b" ascii /* hex encoded string 'ndy\Desktop\unlock.doc.lnk' */
  condition:
    uint16(0) == 0x5c7b and filesize < 3000KB and ( 1 of ($x*) or 2 of them )
}