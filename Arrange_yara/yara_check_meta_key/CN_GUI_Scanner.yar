rule CN_GUI_Scanner {
  meta:
    author = "Spider"
    comment = "None"
    date = "04.10.2014"
    description = "Detects an unknown GUI scanner tool - CN background"
    family = "None"
    hacker = "None"
    hash = "3c67bbb1911cdaef5e675c56145e1112"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 65
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "good.txt" fullword ascii
    $s2 = "IP.txt" fullword ascii
    $s3 = "xiaoyuer" fullword ascii
    $s0w = "ssh(" fullword wide
    $s1w = ").exe" fullword wide
  condition:
    all of them
}