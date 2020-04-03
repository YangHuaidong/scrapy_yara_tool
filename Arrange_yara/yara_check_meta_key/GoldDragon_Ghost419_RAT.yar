import "pe"
rule GoldDragon_Ghost419_RAT {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-02-03"
    description = "Detects Ghost419 RAT from Gold Dragon report"
    family = "None"
    hacker = "None"
    hash1 = "45bfa1327c2c0118c152c7192ada429c6d4ae03b8164ebe36ab5ba9a84f5d7aa"
    hash2 = "ee7a9a7589cbbcac8b6bf1a3d9c5d1c1ada98e68ac2f43ff93f768661b7e4a85"
    hash3 = "dee482e5f461a8e531a6a7ea4728535aafdc4941a8939bc3c55f6cb28c46ad3d"
    hash4 = "2df9e274ce0e71964aca4183cec01fb63566a907981a9e7384c0d73f86578fe4"
    hash5 = "111ab6aa14ef1f8359c59b43778b76c7be5ca72dc1372a3603cd5814bfb2850d"
    hash6 = "0ca12b78644f7e4141083dbb850acbacbebfd3cfa17a4849db844e3f7ef1bee5"
    hash7 = "ae1b32aac4d8a35e2c62e334b794373c7457ebfaaab5e5e8e46f3928af07cde4"
    hash8 = "c54837d0b856205bd4ae01887aae9178f55f16e0e1a1e1ff59bd18dbc8a3dd82"
    hash9 = "db350bb43179f2a43a1330d82f3afeb900db5ff5094c2364d0767a3e6b97c854"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://goo.gl/rW1yvZ"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; .NET CLR 1.1.4322)" fullword ascii
    $x2 = "WebKitFormBoundarywhpFxMBe19cSjFnG" ascii
    $x3 = "\\Microsoft\\HNC\\" fullword ascii
    $x4 = "\\anternet abplorer" fullword ascii
    $x5 = "%s\\abxplore.exe" fullword ascii
    $x6 = "GHOST419" fullword ascii
    $x7 = "I,m Online. %04d - %02d - %02d - %02d - %02d" fullword ascii
    $x8 = "//////////////////////////regkeyenum//////////////" fullword ascii
    $s1 = "www.GoldDragon.com" fullword ascii
    $s2 = "/c systeminfo >> %s" fullword ascii
    $s3 = "/c dir %s\\ >> %s" fullword ascii
    $s4 = "DownLoading %02x, %02x, %02x" fullword ascii
    $s5 = "Tran_dll.dll" fullword ascii
    $s6 = "MpCmdRunkr.dll" fullword ascii
    $s7 = "MpCmdRun.dll" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 200KB and (
    pe.exports("ExportFunction") or
    1 of ($x*) or
    2 of them
}