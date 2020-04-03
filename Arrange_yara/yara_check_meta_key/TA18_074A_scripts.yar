rule TA18_074A_scripts {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-03-16"
    description = "Detects malware mentioned in TA18-074A"
    family = "None"
    hacker = "None"
    hash1 = "2f159b71183a69928ba8f26b76772ec504aefeac71021b012bd006162e133731"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://www.us-cert.gov/ncas/alerts/TA18-074A"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "Running -s cmd /c query user on " ascii
  condition:
    filesize < 600KB and 2 of them
}