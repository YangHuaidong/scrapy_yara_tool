rule CN_Tools_srss {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-13"
    description = "Chinese Hacktool Set - file srss.bat"
    family = "None"
    hacker = "None"
    hash = "092ab0797947692a247fe80b100fb4df0f9c37a0"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "srss.exe -idx 0 -ip"
    $s1 = "-port 21 -logfilter \"_USER ,_P" ascii
  condition:
    filesize < 100 and all of them
}