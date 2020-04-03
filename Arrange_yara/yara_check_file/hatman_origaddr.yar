rule hatman_origaddr : hatman {
    strings:
        $oaddr_be   = { 3c 60 00 03  60 63 96 f4  4e 80 00 20 }
        $oaddr_le   = { 03 00 60 3c  f4 96 63 60  20 00 80 4e }
    condition:
        $oaddr_be or $oaddr_le
}