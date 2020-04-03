rule simple_backdoor_php {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file simple-backdoor.php.txt"
    family = "None"
    hacker = "None"
    hash = "f091d1b9274c881f8e41b2f96e6b9936"
    judge = "black"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "$cmd = ($_REQUEST['cmd']);" fullword
    $s1 = "<!-- Simple PHP backdoor by DK (http://michaeldaw.org) -->"
    $s2 = "Usage: http://target.com/simple-backdoor.php?cmd=cat+/etc/passwd" fullword
  condition:
    2 of them
}