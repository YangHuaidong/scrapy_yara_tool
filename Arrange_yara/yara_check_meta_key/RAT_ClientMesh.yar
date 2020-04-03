rule RAT_ClientMesh {
  meta:
    author = "Spider"
    comment = "None"
    date = "01.06.2014"
    description = "Detects ClientMesh RAT"
    family = "torct"
    hacker = "None"
    judge = "black"
    reference = "http://malwareconfig.com/stats/ClientMesh"
    threatname = "None"
    threattype = "None"
  strings:
    $string1 = "machinedetails"
    $string2 = "MySettings"
    $string3 = "sendftppasswords"
    $string4 = "sendbrowserpasswords"
    $string5 = "arma2keyMass"
    $string6 = "keylogger"
  condition:
    all of them
}