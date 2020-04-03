rule CN_Honker_nc_MOVE {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Script from disclosed CN Honker Pentest Toolset - file MOVE.txt"
    family = "None"
    hacker = "None"
    hash = "4195370c103ca467cddc8f2724a8e477635be424"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "Destination: http://202.113.20.235/gj/images/2.asp" fullword ascii /* PEStudio Blacklist: strings */
    $s1 = "HOST: 202.113.20.235" fullword ascii /* PEStudio Blacklist: strings */
    $s2 = "MOVE /gj/images/A.txt HTTP/1.1" fullword ascii
  condition:
    filesize < 1KB and all of them
}