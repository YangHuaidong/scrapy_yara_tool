rule _Crystal_php_nshell_php_php_load_shell_php_php {
  meta:
    author = Spider
    comment = None
    date = None
    description = Semi-Auto-generated  - from files Crystal.php.txt, nshell.php.php.txt, load_shell.php.php.txt
    family = nshell
    hacker = None
    hash0 = fdbf54d5bf3264eb1c4bff1fac548879
    hash1 = 4a44d82da21438e32d4f514ab35c26b6
    hash2 = 0c5d227f4aa76785e4760cdcff78a661
    judge = unknown
    reference = None
    super_rule = 1
    threatname = [Crystal]/php.nshell.php.php.load.shell.php.php
    threattype = Crystal
  strings:
    $s0 = "if ($filename != \".\" and $filename != \"..\"){" fullword
    $s1 = "$dires = $dires . $directory;" fullword
    $s4 = "$arr = array_merge($arr, glob(\"*\"));" fullword
  condition:
    2 of them
}