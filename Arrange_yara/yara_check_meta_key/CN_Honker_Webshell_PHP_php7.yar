rule CN_Honker_Webshell_PHP_php7 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Webshell from CN Honker Pentest Toolset - file php7.txt"
    family = "None"
    hacker = "None"
    hash = "05a3f93dbb6c3705fd5151b6ffb64b53bc555575"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "---> '.$ports[$i].'<br>'; ob_flush(); flush(); } } echo '</div>'; return true; }" ascii /* PEStudio Blacklist: strings */
    $s1 = "$getfile = isset($_POST['downfile']) ? $_POST['downfile'] : ''; $getaction = iss" ascii /* PEStudio Blacklist: strings */
  condition:
    filesize < 300KB and all of them
}