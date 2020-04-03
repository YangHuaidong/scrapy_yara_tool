rule ZXshell2_0_rar_Folder_nc {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file nc.exe"
    family = "None"
    hacker = "None"
    hash = "2cd1bf15ae84c5f6917ddb128827ae8b"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "WSOCK32.dll"
    $s1 = "?bSUNKNOWNV"
    $s7 = "p@gram Jm6h)"
    $s8 = "ser32.dllCONFP@"
  condition:
    all of them
}