rule webshell_simple_backdoor {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file simple-backdoor.php"
    family = "None"
    hacker = "None"
    hash = "f091d1b9274c881f8e41b2f96e6b9936"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "$cmd = ($_REQUEST['cmd']);" fullword
    $s1 = "if(isset($_REQUEST['cmd'])){" fullword
    $s4 = "system($cmd);" fullword
  condition:
    2 of them
}