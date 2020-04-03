rule ProjectM_DarkComet_1 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-03-26"
    description = "Detects ProjectM Malware - file cc488690ce442e9f98bac651218f4075ca36c355d8cd83f7a9f5230970d24157"
    family = "None"
    hacker = "None"
    hash = "cc488690ce442e9f98bac651218f4075ca36c355d8cd83f7a9f5230970d24157"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://researchcenter.paloaltonetworks.com/2016/03/unit42-projectm-link-found-between-pakistani-actor-and-operation-transparent-tribe/"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "DarkO\\_2" fullword ascii
    $a1 = "AVICAP32.DLL" fullword ascii
    $a2 = "IDispatch4" fullword ascii
    $a3 = "FLOOD/" fullword ascii
    $a4 = "T<-/HTTP://" fullword ascii
    $a5 = "infoes" fullword ascii
  condition:
    ( uint16(0) == 0x5a4d and filesize < 600KB and 4 of them ) or ( all of them )
}