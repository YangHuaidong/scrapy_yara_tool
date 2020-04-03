rule Duqu2_Sample2 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-07-02"
    description = "Detects Duqu2 Malware"
    family = "None"
    hacker = "None"
    hash1 = "d12cd9490fd75e192ea053a05e869ed2f3f9748bf1563e6e496e7153fb4e6c98"
    hash2 = "5ba187106567e8d036edd5ddb6763f89774c158d2a571e15d76572d8604c22a0"
    hash3 = "6e09e1a4f56ea736ff21ad5e188845615b57e1a5168f4bdaebe7ddc634912de9"
    hash4 = "c16410c49dc40a371be22773f420b7dd3cfd4d8205cf39909ad9a6f26f55718e"
    hash5 = "2ecb26021d21fcef3d8bba63de0c888499110a2b78e4caa6fa07a2b27d87f71b"
    hash6 = "2c9c3ddd4d93e687eb095444cef7668b21636b364bff55de953bdd1df40071da"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://securelist.com/blog/research/70504/the-mystery-of-duqu-2-0-a-sophisticated-cyberespionage-actor-returns/"
    score = 80
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "=<=Q=W=a=g=p=v=|=" fullword ascii
    $s2 = ">#>(>.>3>=>]>d>p>" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 50KB and all of ($s*)
}