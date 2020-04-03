import "pe"

  meta:
    author = "Spider"
    comment = "None"
    copyright = "Kaspersky Lab"
    date = "None"
    description = "Generic detection for samples that enumerate files with encrypted resource called 101"
    family = "None"
    hacker = "None"
    hash = "2cd0a5f1e9bcce6807e57ec8477d222a"
    hash = "c843046e54b755ec63ccb09d0a689674"
    judge = "black"
    reference = "https://securelist.com/blog/research/77725/from-shamoon-to-stonedrill/"
    threatname = "None"
    threattype = "None"
    version = "1.4"
  strings:
    $mz = "This program cannot be run in DOS mode."
    $a1 = "FindFirstFile" ascii wide nocase
    $a2 = "FindNextFile" ascii wide nocase
    $a3 = "FindResource" ascii wide nocase
    $a4 = "LoadResource" ascii wide nocase
  condition:
    uint16(0) == 0x5A4D and
    all of them and
    filesize < 700000 and
    pe.number_of_sections > 4 and
    pe.number_of_resources > 1 and pe.number_of_resources < 15 and
    for any i in (0..pe.number_of_resources - 1):
    (math.entropy(pe.resources[i].offset, pe.resources[i].length) > 7.8) and
    pe.resources[i].id == 101 and
    pe.resources[i].length > 20000 and
    pe.resources[i].language == 0 and
    not ($mz in (pe.resources[i].offset..pe.resources[i].offset + pe.resources[i].length))
}