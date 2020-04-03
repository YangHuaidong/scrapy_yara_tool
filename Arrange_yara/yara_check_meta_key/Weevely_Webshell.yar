rule Weevely_Webshell {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/12/14"
    description = "Weevely Webshell - Generic Rule - heavily scrambled tiny web shell"
    family = "None"
    hacker = "None"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://www.ehacking.net/2014/12/weevely-php-stealth-web-backdoor-kali.html"
    score = 60
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = /\$[a-z]{4} = \$[a-z]{4}\("[a-z][a-z]?",[\s]?"",[\s]?"/ ascii
    $s1 = /\$[a-z]{4} = str_replace\("[a-z][a-z]?","","/ ascii
    $s2 = /\$[a-z]{4}\.\$[a-z]{4}\.\$[a-z]{4}\.\$[a-z]{4}\)\)\); \$[a-z]{4}\(\);/ ascii
    $s4 = /\$[a-z]{4}="[a-zA-Z0-9]{70}/ ascii
  condition:
    uint32(0) == 0x68703f3c and all of ($s*) and filesize > 570 and filesize < 800
}