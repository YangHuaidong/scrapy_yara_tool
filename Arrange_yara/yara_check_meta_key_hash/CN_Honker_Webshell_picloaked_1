rule CN_Honker_Webshell_picloaked_1 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Webshell from CN Honker Pentest Toolset - file 1.gif"
    family = "None"
    hacker = "None"
    hash = "3eab1798cbc9ab3b2c67d3da7b418d07e775db70"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "<?php eval($_POST[" ascii /* PEStudio Blacklist: strings */
    $s1 = ";<%execute(request(" ascii /* PEStudio Blacklist: strings */
    $s3 = "GIF89a" fullword ascii /* Goodware String - occured 318 times */
  condition:
    filesize < 6KB and 2 of them
}