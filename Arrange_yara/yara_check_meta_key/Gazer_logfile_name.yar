rule Gazer_logfile_name {
  meta:
    author = "Spider"
    comment = "None"
    date = "30.08.2017"
    description = "Detects Tura's Gazer malware"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "https://www.welivesecurity.com/2017/08/30/eset-research-cyberespionage-gazer/"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "CVRG72B5.tmp.cvr"
    $s2 = "CVRG1A6B.tmp.cvr"
    $s3 = "CVRG38D9.tmp.cvr"
  condition:
    uint16(0) == 0x5a4d and 1 of them
}