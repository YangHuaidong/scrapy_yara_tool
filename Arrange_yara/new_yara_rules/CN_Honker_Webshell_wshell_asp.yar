rule CN_Honker_Webshell_wshell_asp {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Webshell from CN Honker Pentest Toolset - file wshell-asp.txt"
    family = "None"
    hacker = "None"
    hash = "4a0afdf5a45a759c14e99eb5315964368ca53e9c"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "file1.Write(\"<%response.clear:execute request(\\\"root\\\"):response.End%>\");" fullword ascii /* PEStudio Blacklist: strings */
    $s2 = "hello word !  " fullword ascii /* PEStudio Blacklist: strings */
    $s3 = "root.asp " fullword ascii
  condition:
    filesize < 5KB and all of them
}