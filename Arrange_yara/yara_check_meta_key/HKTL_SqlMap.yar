rule HKTL_SqlMap {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-10-09"
    description = "Detects sqlmap hacktool"
    family = "None"
    hacker = "None"
    hash1 = "9444478b03caf7af853a64696dd70083bfe67f76aa08a16a151c00aadb540fa8"
    judge = "black"
    reference = "https://github.com/sqlmapproject/sqlmap"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "if cmdLineOptions.get(\"sqlmapShell\"):" fullword ascii
    $x2 = "if conf.get(\"dumper\"):" fullword ascii
  condition:
    filesize < 50KB and 1 of them
}