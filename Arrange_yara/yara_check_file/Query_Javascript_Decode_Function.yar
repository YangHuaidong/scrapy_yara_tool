rule Query_Javascript_Decode_Function {
  meta:
    author = Spider
    comment = None
    date = None
    description = Detects malware mentioned in TA18-074A
    family = Function
    hacker = None
    judge = unknown
    name = Query_Javascript_Decode_Function
    reference = None
    threatname = Query[Javascript]/Decode.Function
    threattype = Javascript
  strings:
    $decode1 = { 72 65 70 6c 61 63 65 28 2f 5b 5e 41 2d 5a 61 2d 7a 30 2d 39 5c 2b 5c 2f 5c 3d 5d 2f 67 2c 22 22 29 3b }
    $decode2 = {22 41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F 50 51 52 53 54 55 56 57 58 59 5A 61 62 63 64 65 66 67 68 69 6A 6B 6C 6D 6E 6F 70 71 72 73 74 75 76 77 78 79 7A 30 31 32 33 34 35 36 37 38 39 2B 2F 3D 22 2E 69 6E 64 65 78 4F 66 28 ?? 2E 63 68 61 72 41 74 28 ?? 2B 2B 29 29}
    $decode3 = {3D ?? 3C 3C 32 7C ?? 3E 3E 34 2C ?? 3D 28 ?? 26 31 35 29 3C 3C 34 7C ?? 3E 3E 32 2C ?? 3D 28 ?? 26 33 29 3C 3C 36 7C ?? 2C ?? 2B 3D [1-2] 53 74 72 69 6E 67 2E 66 72 6F 6D 43 68 61 72 43 6F 64 65 28 ?? 29 2C 36 34 21 3D ?? 26 26 28 ?? 2B 3D 53 74 72 69 6E 67 2E 66 72 6F 6D 43 68 61 72 43 6F 64 65 28 ?? 29}
    $decode4 = {73 75 62 73 74 72 69 6E 67 28 34 2C ?? 2E 6C 65 6E 67 74 68 29}
  condition:
    filesize < 20KB and all of ($decode*)
}