rule thelast_orice2 {
  meta:
    author = Spider
    comment = None
    date = None
    description = Webshells Auto-generated - file orice2.php
    family = None
    hacker = None
    hash = aa63ffb27bde8d03d00dda04421237ae
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    threatname = thelast[orice2
    threattype = orice2.yar
  strings:
    $s0 = " $aa = $_GET['aa'];"
    $s1 = "echo $aa;"
  condition:
    all of them
}