rule Moroccan_Spamers_Ma_EditioN_By_GhOsT_php {
  meta:
    author = Spider
    comment = None
    date = None
    description = Semi-Auto-generated  - file Moroccan Spamers Ma-EditioN By GhOsT.php.txt
    family = EditioN
    hacker = None
    hash = d1b7b311a7ffffebf51437d7cd97dc65
    judge = unknown
    reference = None
    threatname = Moroccan[Spamers]/Ma.EditioN.By.GhOsT.php
    threattype = Spamers
  strings:
    $s0 = ";$sd98=\"john.barker446@gmail.com\""
    $s1 = "print \"Sending mail to $to....... \";"
    $s2 = "<td colspan=\"2\" width=\"715\" background=\"/simparts/images/cellpic1.gif\" hei"
  condition:
    1 of them
}