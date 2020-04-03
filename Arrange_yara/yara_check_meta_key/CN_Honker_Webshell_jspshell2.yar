rule CN_Honker_Webshell_jspshell2 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Webshell from CN Honker Pentest Toolset - file jspshell2.txt"
    family = "None"
    hacker = "None"
    hash = "cc7bc1460416663012fc93d52e2078c0a277ff79"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s10 = "if (cmd == null) cmd = \"cmd.exe /c set\";" fullword ascii /* PEStudio Blacklist: strings */
    $s11 = "if (program == null) program = \"cmd.exe /c net start > \"+SHELL_DIR+\"/Log.txt" ascii /* PEStudio Blacklist: strings */
  condition:
    filesize < 424KB and all of them
}