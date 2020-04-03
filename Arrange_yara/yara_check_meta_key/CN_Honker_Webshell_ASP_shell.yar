rule CN_Honker_Webshell_ASP_shell {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Webshell from CN Honker Pentest Toolset - file shell.txt"
    family = "None"
    hacker = "None"
    hash = "b7b34215c2293ace70fc06cbb9ce73743e867289"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "xPost.Open \"GET\",\"http://www.i0day.com/1.txt\",False //" fullword ascii /* PEStudio Blacklist: strings */
    $s2 = "sGet.SaveToFile Server.MapPath(\"test.asp\"),2 //" fullword ascii /* PEStudio Blacklist: strings */
    $s3 = "http://hi.baidu.com/xahacker/fuck.txt" fullword ascii
  condition:
    filesize < 1KB and all of them
}