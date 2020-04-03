rule CN_Honker_Webshell_PHP_php2 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Webshell from CN Honker Pentest Toolset - file php2.txt"
    family = "None"
    hacker = "None"
    hash = "bf12e1d741075cd1bd324a143ec26c732a241dea"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "$OOO0O0O00=__FILE__;$OOO000000=urldecode('" ascii /* PEStudio Blacklist: strings */
    $s2 = "<?php // Black" fullword ascii
  condition:
    filesize < 12KB and all of them
}