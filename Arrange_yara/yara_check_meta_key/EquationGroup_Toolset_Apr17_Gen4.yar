rule EquationGroup_Toolset_Apr17_Gen4 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-04-15"
    description = "Detects EquationGroup Tool - April Leak"
    family = "None"
    hacker = "None"
    hash1 = "fe7ce2fdb245c62e4183c728bc97e966a98fdc8ffd795ed09da23f96e85dcdcd"
    hash10 = "d94b99908f528fa4deb56b11eac29f6a6e244a7b3aac36b11b807f2f74c6d8be"
    hash11 = "4b07d9d964b2c0231c1db7526237631bb83d0db80b3c9574cc414463703462d3"
    hash12 = "30b63abde1e871c90df05137ec08df3fa73dedbdb39cb4bd2a2df4ca65bc4e53"
    hash13 = "02c1b08224b7ad4ac3a5b7b8e3268802ee61c1ec30e93e392fa597ae3acc45f7"
    hash14 = "690f09859ddc6cd933c56b9597f76e18b62a633f64193a51f76f52f67bc2f7f0"
    hash2 = "0989bfe351342a7a1150b676b5fd5cbdbc201b66abcb23137b1c4de77a8f61a6"
    hash3 = "270850303e662be53d90fa60a9e5f4bd2bfb95f92a046c77278257631d9addf4"
    hash4 = "7a086c0acb6df1fa304c20733f96e898d21ca787661270f919329fadfb930a6e"
    hash5 = "c236e0d9c5764f223bd3d99f55bd36528dfc0415e14f5fde1e5cdcada14f4ec0"
    hash6 = "9d98e044eedc7272823ba8ed80dff372fde7f3d1bece4e5affb21e16f7381eb2"
    hash7 = "dfce29df4d198c669a87366dd56a7426192481d794f71cd5bb525b08132ed4f7"
    hash8 = "87fdc6c32b9aa8ae97c7efbbd5c9ae8ec5595079fc1488f433beef658efcb4e9"
    hash9 = "722f034ba634f45c429c7dafdbff413c08976b069a6b30ec91bfa5ce2e4cda26"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
    super_rule = 1
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "[+] \"TargetPort\"      %hu" fullword ascii
    $x2 = "---<<<  Complete  >>>---" fullword ascii
    $x3 = "[+] \"NetworkTimeout\"  %hu" fullword ascii
    $op1 = { 46 83 c4 0c 83 fe 0c 0f 8c 5e ff ff ff b8 }
  condition:
    ( uint16(0) == 0x5a4d and filesize < 150KB and ( 1 of ($x*) or 2 of them ) )
}