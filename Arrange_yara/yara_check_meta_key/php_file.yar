rule php_file {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-22"
    description = "Laudanum Injector Tools - file file.php"
    family = "None"
    hacker = "None"
    hash = "7421d33e8007c92c8642a36cba7351c7f95a4335"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://laudanum.inguardians.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "$allowedIPs =" fullword ascii /* PEStudio Blacklist: strings */
    $s2 = "<a href=\"<?php echo $_SERVER['PHP_SELF']  ?>\">Home</a><br/>" fullword ascii /* PEStudio Blacklist: strings */
    $s3 = "$dir  = isset($_GET[\"dir\"])  ? $_GET[\"dir\"]  : \".\";" fullword ascii
    $s4 = "$curdir .= substr($curdir, -1) != \"/\" ? \"/\" : \"\";" fullword ascii
  condition:
    filesize < 10KB and all of them
}