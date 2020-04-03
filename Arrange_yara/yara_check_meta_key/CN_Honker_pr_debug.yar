rule CN_Honker_pr_debug {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Sample from CN Honker Pentest Toolset - file debug.exe"
    family = "None"
    hacker = "None"
    hash = "d11e6c6f675b3be86e37e50184dadf0081506a89"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "-->Got WMI process Pid: %d " ascii /* PEStudio Blacklist: strings */
    $s2 = "This exploit will execute \"net user temp 123456 /add & net localg" ascii /* PEStudio Blacklist: strings */
  condition:
    uint16(0) == 0x5a4d and filesize < 820KB and all of them
}