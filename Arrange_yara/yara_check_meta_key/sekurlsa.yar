rule sekurlsa {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-13"
    description = "Chinese Hacktool Set - file sekurlsa.dll"
    family = "None"
    hacker = "None"
    hash = "6acecd18fc7da1c5eb0d04e848aae9ce59d2b1b5"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "Bienvenue dans un processus distant" fullword wide
    $s2 = "Format d'appel invalide : addLogonSession [idSecAppHigh] idSecAppLow Utilisateur" wide
    $s3 = "SECURITY\\Policy\\Secrets" fullword wide
    $s4 = "Injection de donn" fullword wide
  condition:
    uint16(0) == 0x5a4d and filesize < 1150KB and all of them
}