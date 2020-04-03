rule CN_Honker_Webshell_Injection_Transit_jmPost {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Webshell from CN Honker Pentest Toolset - file jmPost.asp"
    family = "None"
    hacker = "None"
    hash = "f80ec26bbdc803786925e8e0450ad7146b2478ff"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "response.write  PostData(JMUrl,JmStr,JmCok,JmRef)" fullword ascii /* PEStudio Blacklist: strings */
    $s2 = "JmdcwName=request(\"jmdcw\")" fullword ascii /* PEStudio Blacklist: strings */
  condition:
    filesize < 9KB and all of them
}