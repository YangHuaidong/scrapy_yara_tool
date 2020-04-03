rule CN_Honker_Webshell_phpwebbackup {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Webshell from CN Honker Pentest Toolset - file phpwebbackup.php"
    family = "None"
    hacker = "None"
    hash = "c788cb280b7ad0429313837082fe84e9a49efab6"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "<?php // Code By isosky www.nbst.org" fullword ascii
    $s2 = "$OOO0O0O00=__FILE__;$OOO000000=urldecode('" ascii /* PEStudio Blacklist: strings */
  condition:
    uint16(0) == 0x3f3c and filesize < 67KB and all of them
}