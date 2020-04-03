rule CN_Honker_Webshell_Serv_U_serv_u {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Webshell from CN Honker Pentest Toolset - file serv-u.php"
    family = "None"
    hacker = "None"
    hash = "1c6415a247c08a63e3359b06575b36017befc0c0"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "@readfile(\"c:\\\\winnt\\\\system32\\" fullword ascii /* PEStudio Blacklist: strings */
    $s2 = "$sendbuf = \"PASS \".$_POST[\"password\"].\"\\r\\n\";" fullword ascii /* PEStudio Blacklist: strings */
    $s3 = "$cmd=\"cmd /c rundll32.exe $path,install $openPort $activeStr\";" fullword ascii /* PEStudio Blacklist: strings */
  condition:
    filesize < 435KB and all of them
}