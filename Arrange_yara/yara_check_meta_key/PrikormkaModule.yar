rule PrikormkaModule {
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
    $str1 = { 6d 70 2e 64 6c 6c 00 53 74 61 72 74 69 6e 67 00 }
    $str2 = { 68 6c 70 75 63 74 66 2e 64 6c 6c 00 43 79 63 6c 65 }
    $str3 = { 00 6b 6c 2e 64 6c 6c 00 53 74 61 72 74 69 6e 67 00 }
    $str4 = { 69 6f 6d 75 73 2e 64 6c 6c 00 53 74 61 72 74 69 6e 67 }
    $str5 = { 61 74 69 6d 6c 2e 64 6c 6c 00 4b 69 63 6b 49 6e 50 6f 69 6e 74 }
    $str6 = { 73 6e 6d 2e 64 6c 6c 00 47 65 74 52 65 61 64 79 46 6f 72 44 65 61 64 }
    $str7 = { 73 63 72 73 68 2e 64 6c 6c 00 47 65 74 52 65 61 64 79 46 6f 72 44 65 61 64 }
    $str8 = { 50 52 55 5c 17 51 58 17 5e 4a }
    $str9 = { 60 4a 55 55 4e 53 58 4b 17 52 57 17 5e 4a }
    $str10 = { 55 52 5d 4e 5b 4a 5d 17 51 58 17 5e 4a }
    $str11 = { 60 4a 55 55 4e 61 17 51 58 17 5e 4a }
    $str12 = { 39 5d 17 1d 1c 0a 3c 57 59 3b 1c 1e 57 58 4c 54 0f }
    $str13 = "ZxWinDeffContex" ascii wide
    $str14 = "Paramore756Contex43" wide
    $str15 = "Zw_&one@ldrContext43" wide
    $str16 = "A95BL765MNG2GPRS"
    $str17 = "helpldr.dll" wide fullword
    $str18 = "swma.dll" wide fullword
    $str19 = "iomus.dll" wide fullword
    $str20 = "atiml.dll"  wide fullword
    $str21 = "hlpuctf.dll" wide fullword
    $str22 = "hauthuid.dll" ascii wide fullword
    $str23 = "[roboconid][%s]" ascii fullword
    $str24 = "[objectset][%s]" ascii fullword
    $str25 = "rbcon.ini" wide fullword
    $str26 = "%s%02d.%02d.%02d_%02d.%02d.%02d.skw" ascii fullword
    $str27 = "%02d.%02d.%02d_%02d.%02d.%02d.%02d.rem" wide fullword
    $str28 = ":\\!PROJECTS!\\Mina\\2015\\" ascii
    $str29 = "\\PZZ\\RMO\\" ascii
    $str30 = ":\\work\\PZZ" ascii
    $str31 = "C:\\Users\\mlk\\" ascii
    $str32 = ":\\W o r k S p a c e\\" ascii
    $str33 = "D:\\My\\Projects_All\\2015\\" ascii
    $str34 = "\\TOOLS PZZ\\Bezzahod\\" ascii
  condition:
    uint16(0) == 0x5a4d and (any of ($str*))
}