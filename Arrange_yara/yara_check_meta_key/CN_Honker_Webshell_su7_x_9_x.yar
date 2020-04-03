rule CN_Honker_Webshell_su7_x_9_x {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Webshell from CN Honker Pentest Toolset - file su7.x-9.x.asp"
    family = "None"
    hacker = "None"
    hash = "808396b51023cc8356f8049cfe279b349ca08f1a"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "returns=httpopen(\"LoginID=\"&user&\"&FullName=&Password=\"&pass&\"&ComboPasswor" ascii /* PEStudio Blacklist: strings */
    $s1 = "returns=httpopen(\"\",\"POST\",\"http://127.0.0.1:\"&port&\"/Admin/XML/User.xml?" ascii /* PEStudio Blacklist: strings */
  condition:
    filesize < 59KB and all of them
}