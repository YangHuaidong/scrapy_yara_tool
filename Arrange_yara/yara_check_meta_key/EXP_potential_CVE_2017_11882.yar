rule EXP_potential_CVE_2017_11882 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "None"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "https://www.reversinglabs.com/newsroom/news/reversinglabs-yara-rule-detects-cobalt-strike-payload-exploiting-cve-2017-11882.html"
    threatname = "None"
    threattype = "None"
  strings:
    $docfilemagic = { d0 cf 11 e0 a1 b1 1a e1 }
    $equation1 = "Equation Native" wide ascii
    $equation2 = "Microsoft Equation 3.0" wide ascii
    $mshta = "mshta"
    $http = "http://"
    $https = "https://"
    $cmd = "cmd" fullword
    $pwsh = "powershell"
    $exe = ".exe"
    $address = { 12 0c 43 00 }
  condition:
    uint16(0) == 0xcfd0 and $docfilemagic at 0 and
    any of ($mshta, $http, $https, $cmd, $pwsh, $exe) and any of ($equation1, $equation2) and $address
}