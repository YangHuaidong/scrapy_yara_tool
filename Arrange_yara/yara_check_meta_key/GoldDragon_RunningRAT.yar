import "pe"
rule GoldDragon_RunningRAT {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-02-03"
    description = "Detects Running RAT from Gold Dragon report"
    family = "None"
    hacker = "None"
    hash1 = "0852f2c5741997d8899a34bb95c349d7a9fb7277cd0910656c3ce37a6f11cb88"
    hash2 = "2981e1a1b3c395cee6e4b9e6c46d062cf6130546b04401d724750e4c8382c863"
    hash3 = "7aa99ebc49a130f07304ed25655862a04cc20cb59d129e1416a7dfa04f7d3e51"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://goo.gl/rW1yvZ"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "C:\\USERS\\WIN7_x64\\result.log" fullword wide
    $x2 = "rundll32.exe %s RunningRat" fullword ascii
    $x3 = "SystemRat.dll" fullword ascii
    $x4 = "rundll32.exe %s ExportFunction" fullword ascii
    $x5 = "rundll32.exe \"%s\" RunningRat" fullword ascii
    $x6 = "ixeorat.bin" fullword ascii
    $x7 = "C:\\USERS\\Public\\result.log" fullword ascii
    $a1 = "emanybtsohteg" fullword ascii /* reversed goodware string 'gethostbyname' */
    $a2 = "tekcosesolc" fullword ascii /* reversed goodware string 'closesocket' */
    $a3 = "emankcosteg" fullword ascii /* reversed goodware string 'getsockname' */
    $a4 = "emantsohteg" fullword ascii /* reversed goodware string 'gethostname' */
    $a5 = "tpokcostes" fullword ascii /* reversed goodware string 'setsockopt' */
    $a6 = "putratSASW" fullword ascii /* reversed goodware string 'WSAStartup' */
    $s1 = "ParentDll.dll" fullword ascii
    $s2 = "MR - Already Existed" fullword ascii
    $s3 = "MR First Started, Registed OK!" fullword ascii
    $s4 = "RM-M : LoadResource OK!" fullword ascii
    $s5 = "D:\\result.log" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 300KB and (
    pe.imphash() == "c78ccc8f02286648c4373d3bf03efc43" or
    pe.exports("RunningRat") or
    1 of ($x*) or
    5 of ($a*) or
    3 of ($s*)
}