rule CN_Honker_Webshell_udf_udf {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Webshell from CN Honker Pentest Toolset - file udf.php"
    family = "None"
    hacker = "None"
    hash = "df63372ccab190f2f1d852f709f6b97a8d9d22b9"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "<?php // Source  My : Meiam  " fullword ascii /* PEStudio Blacklist: strings */
    $s2 = "$OOO0O0O00=__FILE__;$OOO000000=urldecode('" ascii /* PEStudio Blacklist: strings */
  condition:
    filesize < 430KB and all of them
}