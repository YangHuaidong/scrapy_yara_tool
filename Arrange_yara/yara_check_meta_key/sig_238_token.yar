rule sig_238_token {
  meta:
    author = "Spider"
    comment = "None"
    date = "23.11.14"
    description = "Disclosed hacktool set (old stuff) - file token.exe"
    family = "None"
    hacker = "None"
    hash = "c52bc6543d4281aa75a3e6e2da33cfb4b7c34b14"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 60
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "Logon.exe" fullword ascii
    $s1 = "Domain And User:" fullword ascii
    $s2 = "PID=Get Addr$(): One" fullword ascii
    $s3 = "Process " fullword ascii
    $s4 = "psapi.dllK" fullword ascii
  condition:
    all of them
}