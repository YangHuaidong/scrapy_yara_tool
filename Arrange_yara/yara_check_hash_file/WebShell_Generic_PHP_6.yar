rule WebShell_Generic_PHP_6 {
  meta:
    author = Spider
    comment = None
    date = None
    description = PHP Webshells Github Archive
    family = 6
    hacker = None
    hash0 = 1a08f5260c4a2614636dfc108091927799776b13
    hash1 = 335a0851304acedc3f117782b61479bbc0fd655a
    hash2 = ca9fcfb50645dc0712abdf18d613ed2196e66241
    hash3 = 36d8782d749638fdcaeed540d183dd3c8edc6791
    hash4 = 03f88f494654f2ad0361fb63e805b6bbfc0c86de
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    super_rule = 1
    threatname = WebShell[Generic]/PHP.6
    threattype = Generic
  strings:
    $s2 = "@eval(stripslashes($_POST['phpcode']));" fullword
    $s5 = "echo shell_exec($com);" fullword
    $s7 = "if($sertype == \"winda\"){" fullword
    $s8 = "function execute($com)" fullword
    $s12 = "echo decode(execute($cmd));" fullword
    $s15 = "echo system($com);" fullword
  condition:
    4 of them
}