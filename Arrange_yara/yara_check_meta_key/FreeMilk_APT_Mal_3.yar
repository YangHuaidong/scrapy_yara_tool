rule FreeMilk_APT_Mal_3 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-10-05"
    description = "Detects malware from FreeMilk campaign"
    family = "None"
    hacker = "None"
    hash1 = "ef40f7ddff404d1193e025081780e32f88883fa4dd496f4189084d772a435cb2"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://researchcenter.paloaltonetworks.com/2017/10/unit42-freemilk-highly-targeted-spear-phishing-campaign/"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "CMD.EXE /C \"%s\"" fullword wide
    $s2 = "\\command\\start.exe" fullword wide
    $s3 = ".bat;.com;.cmd;.exe" fullword wide
    $s4 = "Unexpected failure opening HKCR key: %d" fullword ascii
  condition:
    ( uint16(0) == 0x5a4d and filesize < 900KB and all of them )
}