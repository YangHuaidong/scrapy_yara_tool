rule APT30_Generic_E {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015/04/13"
    description = "FireEye APT30 Report Sample - file 8ff473bedbcc77df2c49a91167b1abeb"
    family = "None"
    hacker = "None"
    hash1 = "1dbb584e19499e26398fb0a7aa2a01b7"
    hash2 = "572c9cd4388699347c0b2edb7c6f5e25"
    hash3 = "8ff473bedbcc77df2c49a91167b1abeb"
    hash4 = "a813eba27b2166620bd75029cc1f04b0"
    hash5 = "b5546842e08950bc17a438d785b5a019"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "Nkfvtyvn}" ascii
    $s6 = "----------------g_nAV=%d,hWnd:0x%X,className:%s,Title:%s,(%d,%d,%d,%d),BOOL=%d" fullword ascii
  condition:
    filesize < 100KB and uint16(0) == 0x5A4D and all of them
}