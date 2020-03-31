rule remsec_executable_blob_parser {
  meta:
    author = Spider
    comment = None
    copyright = Symantec
    date = 2016/08/08
    description = Detects malware from Symantec's Strider APT report
    family = parser
    hacker = None
    judge = unknown
    reference = http://www.symantec.com/connect/blogs/strider-cyberespionage-group-turns-eye-sauron-targets
    score = 80
    threatname = remsec[executable]/blob.parser
    threattype = executable
  strings:
    $code = { ( 0F 82 ?? ?? 00 00 | 72 ?? ) ( 80 | 41 80 ) ( 7? | 7C 24 ) 04 02 ( 0F 85 ?? ?? 00 00 | 75 ?? ) ( 81 | 41 81 ) ( 3? | 3C 24 | 7D 00 ) 02 AA 02 C1 ( 0F 85 ?? ?? 00 00 | 75 ?? ) ( 8B | 41 8B | 44 8B | 45 8B ) ( 4? | 5? | 6? | 7? | ?4 24 | ?C 24 ) 06 }
  condition:
    all of them
}