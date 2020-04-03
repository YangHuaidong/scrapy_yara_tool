rule SUSP_JAVA_Class_with_VBS_Content {
  meta:
    author = "Spider"
    comment = "None"
    date = "2019-01-03"
    description = "Detects a JAVA class file with strings known from VBS files"
    family = "None"
    hacker = "None"
    hash1 = "e0112efb63f2b2ac3706109a233963c19750b4df0058cc5b9d3fa1f1280071eb"
    judge = "black"
    reference = "https://www.menlosecurity.com/blog/a-jar-full-of-problems-for-financial-services-companies"
    score = 60
    threatname = "None"
    threattype = "None"
  strings:
    $a1 = "java/lang/String" ascii
    $s1 = ".vbs" ascii
    $s2 = "createNewFile" fullword ascii
    $s3 = "wscript" fullword ascii nocase
  condition:
    uint16(0) == 0xfeca and filesize < 100KB and $a1 and 3 of ($s*)
}