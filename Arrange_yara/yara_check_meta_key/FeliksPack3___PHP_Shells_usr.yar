rule FeliksPack3___PHP_Shells_usr {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file usr.php"
    family = "None"
    hacker = "None"
    hash = "ade3357520325af50c9098dc8a21a024"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "<?php $id_info = array('notify' => 'off','sub' => 'aasd','s_name' => 'nurullahor"
  condition:
    all of them
}