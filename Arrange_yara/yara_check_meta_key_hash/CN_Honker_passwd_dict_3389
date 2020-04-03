rule CN_Honker_passwd_dict_3389 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Script from disclosed CN Honker Pentest Toolset - file 3389.txt"
    family = "None"
    hacker = "None"
    hash = "2897e909e48a9f56ce762244c3a3e9319e12362f"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "654321" fullword ascii /* reversed goodware string '123456' */
    $s1 = "admin123" fullword ascii /* PEStudio Blacklist: strings */
    $s2 = "admin123456" fullword ascii /* PEStudio Blacklist: strings */
    $s3 = "administrator" fullword ascii /* PEStudio Blacklist: strings */ /* Goodware String - occured 2 times */
    $s4 = "passwd" fullword ascii /* PEStudio Blacklist: strings */ /* Goodware String - occured 42 times */
    $s5 = "password" fullword ascii /* PEStudio Blacklist: strings */ /* Goodware String - occured 244 times */
    $s7 = "12345678" fullword ascii /* Goodware String - occured 29 times */
  condition:
    filesize < 1KB and all of them
}