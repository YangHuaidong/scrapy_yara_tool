rule sig_238_eee {
  meta:
    author = "Spider"
    comment = "None"
    date = "23.11.14"
    description = "Disclosed hacktool set (old stuff) - file eee.exe"
    family = "None"
    hacker = "None"
    hash = "236916ce2980c359ff1d5001af6dacb99227d9cb"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 60
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "szj1230@yesky.com" fullword wide
    $s3 = "C:\\Program Files\\DevStudio\\VB\\VB5.OLB" fullword ascii
    $s4 = "MailTo:szj1230@yesky.com" fullword wide
    $s5 = "Command1_Click" fullword ascii
    $s7 = "software\\microsoft\\internet explorer\\typedurls" fullword wide
    $s11 = "vb5chs.dll" fullword ascii
    $s12 = "MSVBVM50.DLL" fullword ascii
  condition:
    all of them
}