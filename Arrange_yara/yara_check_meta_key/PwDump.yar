rule PwDump {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014-04-24"
    description = "PwDump 6 variant"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "None"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s5 = "Usage: %s [-x][-n][-h][-o output_file][-u user][-p password][-s share] machineNa"
    $s6 = "Unable to query service status. Something is wrong, please manually check the st"
    $s7 = "pwdump6 Version %s by fizzgig and the mighty group at foofus.net" fullword
  condition:
    1 of them
}