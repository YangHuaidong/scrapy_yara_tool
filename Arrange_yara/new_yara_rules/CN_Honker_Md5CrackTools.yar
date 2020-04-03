rule CN_Honker_Md5CrackTools {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Sample from CN Honker Pentest Toolset - file Md5CrackTools.exe"
    family = "None"
    hacker = "None"
    hash = "9dfd9c9923ae6f6fe4cbfa9eb69688269285939c"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0)" fullword ascii /* PEStudio Blacklist: agent */
    $s2 = ",<a href='index.php?c=1&type=md5&hash=" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 4580KB and all of them
}