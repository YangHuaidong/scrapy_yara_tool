rule Hacktools_CN_Panda_tesksd {
  meta:
    author = "Spider"
    comment = "None"
    date = "17.11.14"
    description = "Disclosed hacktool set - file tesksd.jpg"
    family = "None"
    hacker = "None"
    hash = "922147b3e1e6cf1f5dd5f64a4e34d28bdc9128cb"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 60
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "name=\"Microsoft.Windows.Common-Controls\" " fullword ascii
    $s1 = "ExeMiniDownload.exe" fullword wide
    $s16 = "POST %Hs" fullword ascii
  condition:
    all of them
}