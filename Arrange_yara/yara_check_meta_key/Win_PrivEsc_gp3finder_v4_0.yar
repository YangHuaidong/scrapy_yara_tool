rule Win_PrivEsc_gp3finder_v4_0 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-06-02"
    description = "Detects a tool that can be used for privilege escalation - file gp3finder_v4.0.exe"
    family = "None"
    hacker = "None"
    hash1 = "7d34e214ef2ca33516875fb91a72d5798f89b9ea8964d3990f99863c79530c06"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://grimhacker.com/2015/04/10/gp3finder-group-policy-preference-password-finder/"
    score = 80
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "Check for and attempt to decrypt passwords on share" ascii
    $x2 = "Failed to auto get and decrypt passwords. {0}s/" fullword ascii
    $x3 = "GPPPFinder - Group Policy Preference Password Finder" fullword ascii
  condition:
    ( uint16(0) == 0x5a4d and 1 of ($x*) ) or ( all of them )
}