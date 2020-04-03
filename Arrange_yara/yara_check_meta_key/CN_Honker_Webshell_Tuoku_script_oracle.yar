rule CN_Honker_Webshell_Tuoku_script_oracle {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Webshell from CN Honker Pentest Toolset - file oracle.jsp"
    family = "None"
    hacker = "None"
    hash = "fc7043aaac0ee2d860d11f18ddfffbede9d07957"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "String url=\"jdbc:oracle:thin:@localhost:1521:orcl\";" fullword ascii /* PEStudio Blacklist: strings */
    $s2 = "String user=\"oracle_admin\";" fullword ascii /* PEStudio Blacklist: strings */
    $s3 = "String sql=\"SELECT 1,2,3,4,5,6,7,8,9,10 from user_info\";" fullword ascii
  condition:
    filesize < 7KB and all of them
}