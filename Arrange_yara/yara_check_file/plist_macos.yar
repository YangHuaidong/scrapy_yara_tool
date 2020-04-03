rule plist_macos {
    meta:
        hashes = "76eb97aba93979be06dbf0a872518f9514d0bb20b680c887d6fd5cc79dce3681"
    strings:
        $sr1 = "PropertyList-1.0.dtd" fullword
        $sr2 = "<plist"
    condition:
        filesize < 20KB
        and uint32be(0) == 0x3c3f786d
        and all of ($sr*)
        and @sr2[1] < 0x100
}