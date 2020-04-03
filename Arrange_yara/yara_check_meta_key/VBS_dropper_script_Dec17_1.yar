rule VBS_dropper_script_Dec17_1 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-01-01"
    description = "Detects a supicious VBS script that drops an executable"
    family = "None"
    hacker = "None"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Internal Research"
    score = 80
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "TVpTAQEAAAAEAA" // 14 samples in goodware archive
    $s2 = "TVoAAAAAAAAAAA" // 26 samples in goodware archive
    $s3 = "TVqAAAEAAAAEAB" // 75 samples in goodware archive
    $s4 = "TVpQAAIAAAAEAA" // 168 samples in goodware archive
    $s5 = "TVqQAAMAAAAEAA" // 28,529 samples in goodware archive
    $a1 = "= CreateObject(\"Wscript.Shell\")" fullword ascii
  condition:
    filesize < 600KB and $a1 and 1 of ($s*)
}