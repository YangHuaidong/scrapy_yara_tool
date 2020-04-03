rule CN_Hacktool_ScanPort_Portscanner {
  meta:
    author = "Spider"
    comment = "None"
    date = "12.10.2014"
    description = "Detects a chinese Portscanner named ScanPort"
    family = "None"
    hacker = "None"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "LScanPort" fullword wide
    $s1 = "LScanPort Microsoft" fullword wide
    $s2 = "www.yupsoft.com" fullword wide
  condition:
    all of them
}