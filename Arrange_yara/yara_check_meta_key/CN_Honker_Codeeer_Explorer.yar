rule CN_Honker_Codeeer_Explorer {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Sample from CN Honker Pentest Toolset - file Codeeer Explorer.exe"
    family = "None"
    hacker = "None"
    hash = "f32e05f3fefbaa2791dd750e4a3812581ce0f205"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s2 = "Codeeer Explorer.exe" fullword wide /* PEStudio Blacklist: strings */
    $s12 = "webBrowser1_ProgressChanged" fullword ascii /* PEStudio Blacklist: strings */
  condition:
    uint16(0) == 0x5a4d and filesize < 470KB and all of them
}