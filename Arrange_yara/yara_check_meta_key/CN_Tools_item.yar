rule CN_Tools_item {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-13"
    description = "Chinese Hacktool Set - file item.php"
    family = "None"
    hacker = "None"
    hash = "a584db17ad93f88e56fd14090fae388558be08e4"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "$sURL = \"http://\".$sServer.\"/\".$sWget;" fullword ascii
    $s2 = "$sURL = \"301:http://\".$sServer.\"/\".$sWget;" fullword ascii
    $s3 = "$sWget=\"index.asp\";" fullword ascii
    $s4 = "$aURL += array(\"scheme\" => \"\", \"host\" => \"\", \"path\" => \"\");" fullword ascii
  condition:
    filesize < 4KB and all of them
}