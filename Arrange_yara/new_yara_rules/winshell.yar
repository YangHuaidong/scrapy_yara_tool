rule winshell {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file winshell.exe"
    family = "None"
    hacker = "None"
    hash = "3144410a37dd4c29d004a814a294ea26"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunServices"
    $s1 = "WinShell Service"
    $s2 = "__GLOBAL_HEAP_SELECTED"
    $s3 = "__MSVCRT_HEAP_SELECT"
    $s4 = "Provide Windows CmdShell Service"
    $s5 = "URLDownloadToFileA"
    $s6 = "RegisterServiceProcess"
    $s7 = "GetModuleBaseNameA"
    $s8 = "WinShell v5.0 (C)2002 janker.org"
  condition:
    all of them
}