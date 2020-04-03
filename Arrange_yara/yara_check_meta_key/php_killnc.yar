rule php_killnc {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-22"
    description = "Laudanum Injector Tools - file killnc.php"
    family = "None"
    hacker = "None"
    hash = "c0dee56ee68719d5ec39e773621ffe40b144fda5"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://laudanum.inguardians.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "if ($_SERVER[\"REMOTE_ADDR\"] == $IP)" fullword ascii /* PEStudio Blacklist: strings */
    $s2 = "header(\"HTTP/1.0 404 Not Found\");" fullword ascii
    $s3 = "<?php echo exec('killall nc');?>" fullword ascii /* PEStudio Blacklist: strings */
    $s4 = "<title>Laudanum Kill nc</title>" fullword ascii /* PEStudio Blacklist: strings */
    $s5 = "foreach ($allowedIPs as $IP) {" fullword ascii
  condition:
    filesize < 15KB and 4 of them
}