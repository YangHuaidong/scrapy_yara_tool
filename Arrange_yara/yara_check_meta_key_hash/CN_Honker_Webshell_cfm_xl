rule CN_Honker_Webshell_cfm_xl {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Webshell from CN Honker Pentest Toolset - file xl.cfm"
    family = "None"
    hacker = "None"
    hash = "49c3d16ee970945367a7d6ae86b7ade7cb3b5447"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "<input name=\"DESTINATION\" value=\"" ascii /* PEStudio Blacklist: strings */
    $s1 = "<CFFILE ACTION=\"Write\" FILE=\"#Form.path#\" OUTPUT=\"#Form.cmd#\">" fullword ascii
  condition:
    uint16(0) == 0x433c and filesize < 13KB and all of them
}