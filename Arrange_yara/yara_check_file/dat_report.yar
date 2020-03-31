rule dat_report {
  meta:
    author = Spider
    comment = None
    date = 2015-06-13
    description = Chinese Hacktool Set - file report.dll
    family = None
    hacker = None
    hash = 4582a7c1d499bb96dad8e9b227e9d5de9becdfc2
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = http://tools.zjqhr.com/
    threatname = dat[report
    threattype = report.yar
  strings:
    $s1 = "<a href=\"http://www.xfocus.net\">X-Scan</a>" fullword ascii
    $s2 = "REPORT-ANALYSIS-OF-HOST" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 480KB and all of them
}