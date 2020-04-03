rule CN_Honker_AspxClient {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Sample from CN Honker Pentest Toolset - file AspxClient.exe"
    family = "None"
    hacker = "None"
    hash = "67569a89128f503a459eab3daa2032261507f2d2"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "\\tools\\hashq\\hashq.exe" fullword wide
    $s2 = "\\Release\\CnCerT.CCdoor.Client.pdb" fullword ascii
    $s3 = "\\myshell.mdb" fullword wide /* PEStudio Blacklist: strings */
    $s4 = "injectfile" fullword wide /* PEStudio Blacklist: strings */
  condition:
    uint16(0) == 0x5a4d and filesize < 1000KB and 3 of them
}