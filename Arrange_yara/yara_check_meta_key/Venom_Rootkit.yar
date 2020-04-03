rule Venom_Rootkit {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-01-12"
    description = "Venom Linux Rootkit"
    family = "None"
    hacker = "None"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://security.web.cern.ch/security/venom.shtml"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "%%VENOM%CTRL%MODE%%" ascii fullword
    $s2 = "%%VENOM%OK%OK%%" ascii fullword
    $s3 = "%%VENOM%WIN%WN%%" ascii fullword
    $s4 = "%%VENOM%AUTHENTICATE%%" ascii fullword
    $s5 = ". entering interactive shell" ascii fullword
    $s6 = ". processing ltun request" ascii fullword
    $s7 = ". processing rtun request" ascii fullword
    $s8 = ". processing get request" ascii fullword
    $s9 = ". processing put request" ascii fullword
    $s10 = "venom by mouzone" ascii fullword
    $s11 = "justCANTbeSTOPPED" ascii fullword
  condition:
    filesize < 4000KB and 2 of them
}