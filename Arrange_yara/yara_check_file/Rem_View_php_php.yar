rule Rem_View_php_php {
  meta:
    author = Spider
    comment = None
    date = None
    description = Semi-Auto-generated  - file Rem View.php.php.txt
    family = php
    hacker = None
    hash = 29420106d9a81553ef0d1ca72b9934d9
    judge = unknown
    reference = None
    threatname = Rem[View]/php.php
    threattype = View
  strings:
    $s0 = "$php=\"/* line 1 */\\n\\n// \".mm(\"for example, uncomment next line\").\""
    $s2 = "<input type=submit value='\".mm(\"Delete all dir/files recursive\").\" (rm -fr)'"
    $s4 = "Welcome to phpRemoteView (RemView)"
  condition:
    1 of them
}