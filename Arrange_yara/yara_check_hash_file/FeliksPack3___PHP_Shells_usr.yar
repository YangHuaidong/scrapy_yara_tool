rule FeliksPack3___PHP_Shells_usr {
  meta:
    author = Spider
    comment = None
    date = None
    description = Webshells Auto-generated - file usr.php
    family = PHP
    hacker = None
    hash = ade3357520325af50c9098dc8a21a024
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    threatname = FeliksPack3[]/.PHP.Shells.usr
    threattype = 
  strings:
    $s0 = "<?php $id_info = array('notify' => 'off','sub' => 'aasd','s_name' => 'nurullahor"
  condition:
    all of them
}