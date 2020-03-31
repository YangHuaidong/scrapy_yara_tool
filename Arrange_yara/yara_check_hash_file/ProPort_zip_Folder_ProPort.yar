rule ProPort_zip_Folder_ProPort {
  meta:
    author = Spider
    comment = None
    date = None
    description = Auto-generated rule on file ProPort.exe
    family = ProPort
    hacker = None
    hash = c1937a86939d4d12d10fc44b7ab9ab27
    judge = unknown
    reference = None
    threatname = ProPort[zip]/Folder.ProPort
    threattype = zip
  strings:
    $s0 = "Corrupt Data!"
    $s1 = "K4p~omkIz"
    $s2 = "DllTrojanScan"
    $s3 = "GetDllInfo"
    $s4 = "Compressed by Petite (c)1999 Ian Luck."
    $s5 = "GetFileCRC32"
    $s6 = "GetTrojanNumber"
    $s7 = "TFAKAbout"
  condition:
    all of them
}