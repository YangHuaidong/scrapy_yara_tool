rule Microcin_Sample_4 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-09-26"
    description = "Malware sample mentioned in Microcin technical report by Kaspersky"
    family = "None"
    hacker = "None"
    hash1 = "92c01d5af922bdaacb6b0b2dfbe29e5cc58c45cbee5133932a499561dab616b8"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://securelist.com/files/2017/09/Microcin_Technical-PDF_eng_final.pdf"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "cmd /c dir /a /s \"%s\" > \"%s\"" fullword wide
    $s2 = "ini.dat" fullword wide
    $s3 = "winupdata" fullword wide
    $f1 = "%s\\(%08x%08x)%s" fullword wide
    $f2 = "%s\\d%08x\\d%08x.db" fullword wide
    $f3 = "%s\\u%08x\\u%08x.db" fullword wide
    $f4 = "%s\\h%08x\\h%08x.db" fullword wide
  condition:
    ( uint16(0) == 0x5a4d and filesize < 200KB and all of ($s*) or 5 of them )
}