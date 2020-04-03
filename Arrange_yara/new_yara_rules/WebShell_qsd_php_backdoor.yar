rule WebShell_qsd_php_backdoor {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "PHP Webshells Github Archive - file qsd-php-backdoor.php"
    family = "None"
    hacker = "None"
    hash = "4856bce45fc5b3f938d8125f7cdd35a8bbae380f"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "// A robust backdoor script made by Daniel Berliner - http://www.qsdconsulting.c"
    $s2 = "if(isset($_POST[\"newcontent\"]))" fullword
    $s3 = "foreach($parts as $val)//Assemble the path back together" fullword
    $s7 = "$_POST[\"newcontent\"]=urldecode(base64_decode($_POST[\"newcontent\"]));" fullword
  condition:
    2 of them
}