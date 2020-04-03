rule CN_Honker_Pwdump7_Pwdump7 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Script from disclosed CN Honker Pentest Toolset - file Pwdump7.bat"
    family = "None"
    hacker = "None"
    hash = "67d0e215c96370dcdc681bb2638703c2eeea188a"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "Pwdump7.exe >pass.txt" fullword ascii /* PEStudio Blacklist: strings */
  condition:
    filesize < 1KB and all of them
}