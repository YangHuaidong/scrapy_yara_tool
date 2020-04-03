rule WebShell__CrystalShell_v_1_erne_stres {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "PHP Webshells Github Archive - from files CrystalShell v.1.php, erne.php, stres.php"
    family = "None"
    hacker = "None"
    hash0 = "335a0851304acedc3f117782b61479bbc0fd655a"
    hash1 = "6eb4ab630bd25bec577b39fb8a657350bf425687"
    hash2 = "03f88f494654f2ad0361fb63e805b6bbfc0c86de"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    super_rule = 1
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "<input type='submit' value='  open (shill.txt) '>" fullword
    $s4 = "var_dump(curl_exec($ch));" fullword
    $s7 = "if(empty($_POST['Mohajer22'])){" fullword
    $s10 = "$m=$_POST['curl'];" fullword
    $s13 = "$u1p=$_POST['copy'];" fullword
    $s14 = "if(empty(\\$_POST['cmd'])){" fullword
    $s15 = "$string = explode(\"|\",$string);" fullword
    $s16 = "$stream = imap_open(\"/etc/passwd\", \"\", \"\");" fullword
  condition:
    5 of them
}