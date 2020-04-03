rule webshell_ghost_source_icesword_silic {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - from files ghost_source.php, icesword.php, silic.php"
    family = "None"
    hacker = "None"
    hash0 = "cbf64a56306c1b5d98898468fc1fdbd8"
    hash1 = "6e20b41c040efb453d57780025a292ae"
    hash2 = "437d30c94f8eef92dc2f064de4998695"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 70
    super_rule = 1
    threatname = "None"
    threattype = "None"
  strings:
    $s3 = "if(eregi('WHERE|LIMIT',$_POST['nsql']) && eregi('SELECT|FROM',$_POST['nsql'])) $"
    $s6 = "if(!empty($_FILES['ufp']['name'])){if($_POST['ufn'] != '') $upfilename = $_POST["
  condition:
    all of them
}