rule remsec_executable_blob_32 {
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
    $code = { 31 06 83 c6 04 d1 e8 73 05 35 01 00 00 d0 e2 f0 }
  condition:
    all of them
}