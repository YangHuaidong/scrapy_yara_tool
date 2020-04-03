rule SUSP_PDB_Strings_Keylogger_Backdoor {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-03-23"
    description = "Detects PDB strings used in backdoors or keyloggers"
    family = "None"
    hacker = "None"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Internal Research"
    score = 65
    threatname = "None"
    threattype = "None"
  strings:
    $ = "\\Release\\PrivilegeEscalation"
    $ = "\\Release\\KeyLogger"
    $ = "\\Debug\\PrivilegeEscalation"
    $ = "\\Debug\\KeyLogger"
    $ = "Backdoor\\KeyLogger_"
    $ = "\\ShellCode\\Debug\\"
    $ = "\\ShellCode\\Release\\"
    $ = "\\New Backdoor"
  condition:
    uint16(0) == 0x5a4d and filesize < 1000KB
    and 1 of them
}