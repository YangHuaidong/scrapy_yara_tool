rule rootshell_php {
  meta:
    author = Spider
    comment = None
    date = None
    description = Semi-Auto-generated  - file rootshell.php.txt
    family = None
    hacker = None
    hash = 265f3319075536030e59ba2f9ef3eac6
    judge = unknown
    reference = None
    threatname = rootshell[php
    threattype = php.yar
  strings:
    $s0 = "shells.dl.am"
    $s1 = "This server has been infected by $owner"
    $s2 = "<input type=\"submit\" value=\"Include!\" name=\"inc\"></p>"
    $s4 = "Could not write to file! (Maybe you didn't enter any text?)"
  condition:
    2 of them
}