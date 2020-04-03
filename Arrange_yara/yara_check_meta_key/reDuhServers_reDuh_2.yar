rule reDuhServers_reDuh_2 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-13"
    description = "Chinese Hacktool Set - file reDuh.php"
    family = "None"
    hacker = "None"
    hash = "512d0a3e7bb7056338ad0167f485a8a6fa1532a3"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "errorlog(\"FRONTEND: send_command '\".$data.\"' on port \".$port.\" returned \"." ascii
    $s2 = "$msg = \"newData:\".$socketNumber.\":\".$targetHost.\":\".$targetPort.\":\".$seq" ascii
    $s3 = "errorlog(\"BACKEND: *** Socket key is \".$sockkey);" fullword ascii
  condition:
    filesize < 57KB and all of them
}