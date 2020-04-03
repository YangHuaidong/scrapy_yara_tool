rule CN_Honker_SAMInside {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Sample from CN Honker Pentest Toolset - file SAMInside.exe"
    family = "None"
    hacker = "None"
    hash = "707ba507f9a74d591f4f2e2f165ff9192557d6dd"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "www.InsidePro.com" fullword wide
    $s1 = "SAMInside.exe" fullword wide
  condition:
    uint16(0) == 0x5a4d and filesize < 650KB and all of them
}