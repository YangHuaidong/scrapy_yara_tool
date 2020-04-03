rule remsec_executable_blob_32 {
   meta:
      copyright = "Symantec"
      description = "Detects malware from Symantec's Strider APT report"
      score = 80
      date = "2016/08/08"
      reference = "http://www.symantec.com/connect/blogs/strider-cyberespionage-group-turns-eye-sauron-targets"
   strings:
      $code = { 31 06 83 C6 04 D1 E8 73 05 35 01 00 00 D0 E2 F0 }
   condition:
      all of them
}