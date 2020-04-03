rule BIN_Server {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file Server.exe"
    family = "None"
    hacker = "None"
    hash = "1d5aa9cbf1429bb5b8bf600335916dcd"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "configserver"
    $s1 = "GetLogicalDrives"
    $s2 = "WinExec"
    $s4 = "fxftest"
    $s5 = "upfileok"
    $s7 = "upfileer"
  condition:
    all of them
}