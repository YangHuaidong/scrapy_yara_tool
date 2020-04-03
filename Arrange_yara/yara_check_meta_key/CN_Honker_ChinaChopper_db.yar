rule CN_Honker_ChinaChopper_db {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Script from disclosed CN Honker Pentest Toolset - file db.mdb"
    family = "None"
    hacker = "None"
    hash = "af79ff2689a6b7a90a5d3c0ebe709e42f2a15597"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "http://www.maicaidao.com/server.phpcaidao" fullword wide /* PEStudio Blacklist: strings */
    $s2 = "<O>act=login</O>" fullword wide /* PEStudio Blacklist: strings */
    $s3 = "<H>localhost</H>" fullword wide /* PEStudio Blacklist: strings */
  condition:
    filesize < 340KB and 2 of them
}