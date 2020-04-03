rule SUSP_PDB_Path_Keywords {
  meta:
    author = "Spider"
    comment = "None"
    date = "2019-10-04"
    description = "Detects suspicious PDB paths"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "https://twitter.com/stvemillertime/status/1179832666285326337?s=20"
    threatname = "None"
    threattype = "None"
  strings:
    $ = "Debug\\Shellcode" ascii
    $ = "Release\\Shellcode" ascii
    $ = "Debug\\ShellCode" ascii
    $ = "Release\\ShellCode" ascii
    $ = "Debug\\shellcode" ascii
    $ = "Release\\shellcode" ascii
    $ = "shellcode.pdb" nocase ascii
    $ = "\\ShellcodeLauncher" ascii
    $ = "\\ShellCodeLauncher" ascii
    $ = "Fucker.pdb" ascii
    $ = "\\AVFucker\\" ascii
    $ = "ratTest.pdb" ascii
    $ = "Debug\\CVE_" ascii
    $ = "Release\\CVE_" ascii
    $ = "Debug\\cve_" ascii
    $ = "Release\\cve_" ascii
  condition:
    uint16(0) == 0x5a4d and 1 of them
}