rule DarkComet_Keylogger_File {
  meta:
    author = "Spider"
    comment = "None"
    date = "25.07.14"
    description = "Looks like a keylogger file created by DarkComet Malware"
    family = "None"
    hacker = "None"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 50
    threatname = "None"
    threattype = "None"
  strings:
    $entry = /\n:: [A-Z]/
    $timestamp = /\([0-9]?[0-9]:[0-9][0-9]:[0-9][0-9] [AP]M\)/
  condition:
    uint16(0) == 0x3A3A and #entry > 10 and #timestamp > 10
}