rule item_301 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-13"
    description = "Chinese Hacktool Set - file item-301.php"
    family = "None"
    hacker = "None"
    hash = "15636f0e7dc062437608c1f22b1d39fa15ab2136"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "$sURL = \"301:http://\".$sServer.\"/index.asp\";" fullword ascii
    $s2 = "(gov)\\\\.(cn)$/i\", $aURL[\"host\"])" ascii
    $s3 = "$aArg = explode(\" \", $sContent, 5);" fullword ascii
    $s4 = "$sURL = $aArg[0];" fullword ascii
  condition:
    filesize < 3KB and 3 of them
}