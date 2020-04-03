rule PrikormkaDropper {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "None"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $kd1 = "KDSTORAGE" wide
    $kd2 = "KDSTORAGE_64" wide
    $kd3 = "KDRUNDRV32" wide
    $kd4 = "KDRAR" wide
    $bin1 = { 69 65 04 15 00 14 1e 4a 16 42 08 6c 21 61 24 0f }
    $bin2 = { 76 6f 05 04 16 1b 0d 5e 0d 42 08 6c 20 45 18 16 }
    $bin3 = { 4d 00 4d 00 43 00 00 00 67 00 75 00 69 00 64 00 56 00 47 00 41 00 00 00 5f 00 73 00 76 00 67 00 }
    $inj1 = "?AVCinj2008Dlg@@" ascii
    $inj2 = "?AVCinj2008App@@" ascii
  condition:
    uint16(0) == 0x5a4d and ((any of ($bin*)) or (3 of ($kd*)) or (all of ($inj*)))
}