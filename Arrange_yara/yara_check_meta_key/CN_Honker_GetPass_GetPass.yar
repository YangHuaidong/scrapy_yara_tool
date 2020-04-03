rule CN_Honker_GetPass_GetPass {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Sample from CN Honker Pentest Toolset - file GetPass.exe"
    family = "None"
    hacker = "None"
    hash = "d18d952b24110b83abd17e042f9deee679de6a1a"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "\\only\\Desktop\\" ascii
    $s2 = "To Run As Administuor" ascii /* PEStudio Blacklist: strings */
    $s3 = "Key to EXIT ... & pause > nul" fullword ascii /* PEStudio Blacklist: strings */
  condition:
    uint16(0) == 0x5a4d and filesize < 300KB and all of them
}