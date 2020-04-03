rule WinAgent_BadPatch_2 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-10-20"
    description = "Detects samples mentioned in BadPatch report"
    family = "None"
    hacker = "None"
    hash1 = "106deff16a93c4a4624fe96e3274e1432921c56d5a430834775e5b98861c00ea"
    hash2 = "ece76fdf7e33d05a757ef5ed020140d9367c7319022a889923bbfacccb58f4d7"
    hash3 = "cf53fc8c9ce4e5797cc5ac6f71d4cbc0f2b15f2ed43f38048a5273f40bc09876"
    hash4 = "802a39b22dfacdc2325f8a839377c903b4a7957503106ce6f7aed67e824b82c2"
    hash5 = "278dba3857367824fc2d693b7d96cef4f06cb7fdc52260b1c804b9c90d43646d"
    hash6 = "2941f75da0574c21e4772f015ef38bb623dd4d0c81c263523d431b0114dd847e"
    hash7 = "46f3afae22e83344e4311482a9987ed851b2de282e8127f64d5901ac945713c0"
    hash8 = "27752bbb01abc6abf50e1da3a59fefcce59618016619d68690e71ad9d4a3c247"
    hash9 = "050610cfb3d3100841685826273546c829335a5f4e2e4260461b88367ad9502c"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://goo.gl/RvDwwA"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "myAction=shell_result&serialNumber=" fullword wide
    $s2 = "\\Appdata\\Local\\Google\\Chrome\\User Data\\Default\\Login Data.*" fullword wide
    $s3 = "\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles" fullword wide
    $s4 = "\\Appdata\\Local\\Google\\Chrome\\User Data\\Default\\Cookies.*" fullword wide
    $s5 = "newSHELL[" fullword wide
    $s6 = "\\file1.txt" fullword wide
    $s7 = "myAction=newGIF&serialNumber=" fullword wide
    $s8 = "\\Storege1" fullword wide
    $s9 = "\\Microsoft\\mac.txt" fullword wide
    $s10 = "spytube____:" fullword ascii
    $s11 = "0D0700045F5C5B0312045A04041F40014B1D11004A1F19074A141100011200154B031C04" fullword wide
    $s12 = "16161A1000012B162503151851065A1A0007" fullword wide
    $s13 = "-- SysFile...." fullword wide
  condition:
    ( uint16(0) == 0x5a4d and filesize < 700KB and 3 of them )
}