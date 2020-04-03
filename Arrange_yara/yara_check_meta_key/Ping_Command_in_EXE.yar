rule Ping_Command_in_EXE {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-11-03"
    description = "Detects an suspicious ping command execution in an executable"
    family = "None"
    hacker = "None"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Internal Research"
    score = 60
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "cmd /c ping 127.0.0.1 -n " ascii
  condition:
    uint16(0) == 0x5a4d and all of them
}