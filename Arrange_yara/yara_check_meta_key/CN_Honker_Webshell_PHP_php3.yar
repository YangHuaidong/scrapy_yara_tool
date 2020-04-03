rule CN_Honker_Webshell_PHP_php3 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Webshell from CN Honker Pentest Toolset - file php3.txt"
    family = "None"
    hacker = "None"
    hash = "e2924cb0537f4cdfd6f1bd44caaaf68a73419b9d"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "} elseif(@is_resource($f = @popen($cfe,\"r\"))) {" fullword ascii /* PEStudio Blacklist: strings */
    $s2 = "cf('/tmp/.bc',$back_connect);" fullword ascii /* PEStudio Blacklist: strings */
  condition:
    filesize < 8KB and all of them
}