rule WebShell_php_webshells_pHpINJ {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "PHP Webshells Github Archive - file pHpINJ.php"
    family = "None"
    hacker = "None"
    hash = "75116bee1ab122861b155cc1ce45a112c28b9596"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s3 = "echo '<a href='.$expurl.'> Click Here to Exploit </a> <br />';" fullword
    $s10 = "<form action = \"<?php echo \"$_SERVER[PHP_SELF]\" ; ?>\" method = \"post\">" fullword
    $s11 = "$sql = \"0' UNION SELECT '0' , '<? system(\\$_GET[cpc]);exit; ?>' ,0 ,0 ,0 ,0 IN"
    $s13 = "Full server path to a writable file which will contain the Php Shell <br />" fullword
    $s14 = "$expurl= $url.\"?id=\".$sql ;" fullword
    $s15 = "<header>||   .::News PHP Shell Injection::.   ||</header> <br /> <br />" fullword
    $s16 = "<input type = \"submit\" value = \"Create Exploit\"> <br /> <br />" fullword
  condition:
    1 of them
}