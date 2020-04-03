rule CN_Honker_Webshell_Tuoku_script_mysql {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Webshell from CN Honker Pentest Toolset - file mysql.aspx"
    family = "None"
    hacker = "None"
    hash = "8e242c40aabba48687cfb135b51848af4f2d389d"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "txtpassword.Attributes.Add(\"onkeydown\", \"SubmitKeyClick('btnLogin');\");" fullword ascii /* PEStudio Blacklist: strings */
    $s2 = "connString = string.Format(\"Host = { 0 }; UserName = { 0 }; Password = { 0 }; Databas" ascii /* PEStudio Blacklist: strings */
  condition:
    filesize < 202KB and all of them
}