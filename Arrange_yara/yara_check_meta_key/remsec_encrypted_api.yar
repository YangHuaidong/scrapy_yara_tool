rule remsec_encrypted_api {
  meta:
    author = "Spider"
    comment = "None"
    copyright = "Symantec"
    date = "2016/08/08"
    description = "Detects malware from Symantec's Strider APT report"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "http://www.symantec.com/connect/blogs/strider-cyberespionage-group-turns-eye-sauron-targets"
    score = 80
    threatname = "None"
    threattype = "None"
  strings:
    $open_process = { 91 9a 8f b0 9c 90 8d af 8c 8c 9a ff }
  condition:
    all of them
}