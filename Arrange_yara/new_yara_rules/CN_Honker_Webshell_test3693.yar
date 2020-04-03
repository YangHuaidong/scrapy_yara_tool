rule CN_Honker_Webshell_test3693 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Webshell from CN Honker Pentest Toolset - file test3693.war"
    family = "None"
    hacker = "None"
    hash = "246d629ae3ad980b5bfe7e941fe90b855155dbfc"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "Process p=Runtime.getRuntime().exec(\"cmd /c \"+strCmd);" fullword ascii /* PEStudio Blacklist: strings */
    $s2 = "http://www.topronet.com </font>\",\" <font color=red> Thanks for your support - " ascii /* PEStudio Blacklist: strings */
  condition:
    uint16(0) == 0x4b50 and filesize < 50KB and all of them
}