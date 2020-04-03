rule packager_cve2017_11882 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Attempts to exploit CVE-2017-11882 using Packager"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "https://github.com/rxwx/CVE-2017-11882/blob/master/packager_exec_CVE-2017-11882.py"
    score = 60
    threatname = "None"
    threattype = "None"
  strings:
    $font = { 30 61 30 31 30 38 35 61 35 61 }
    $equation = { 45 71 75 61 74 69 6f 6e 2e 33 }
    $package = { 50 61 63 6b 61 67 65 }
    $header_and_shellcode = /03010[0,1][0-9a-fA-F]{108}00/ ascii nocase
  condition:
    uint32be(0) == 0x7B5C7274 // RTF header
    and all of them
}