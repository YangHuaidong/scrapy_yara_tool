rule settings {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-22"
    description = "Laudanum Injector Tools - file settings.php"
    family = "None"
    hacker = "None"
    hash = "588739b9e4ef2dbb0b4cf630b73295d8134cc801"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://laudanum.inguardians.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "Port: <input name=\"port\" type=\"text\" value=\"8888\">" fullword ascii /* PEStudio Blacklist: strings */
    $s2 = "<li>Reverse Shell - " fullword ascii /* PEStudio Blacklist: strings */
    $s3 = "<li><a href=\"<?php echo plugins_url('file.php', __FILE__);?>\">File Browser</a>" ascii /* PEStudio Blacklist: strings */
  condition:
    filesize < 13KB and all of them
}