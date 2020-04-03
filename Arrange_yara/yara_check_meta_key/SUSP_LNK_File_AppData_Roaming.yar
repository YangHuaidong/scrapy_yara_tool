rule SUSP_LNK_File_AppData_Roaming {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-05-16"
    description = "Detects a suspicious link file that references to AppData Roaming"
    family = "None"
    hacker = "None"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://www.fireeye.com/blog/threat-research/2018/05/deep-dive-into-rig-exploit-kit-delivering-grobios-trojan.html"
    score = 50
    threatname = "None"
    threattype = "None"
  strings:
    $s2 = "AppData" fullword wide
    $s3 = "Roaming" fullword wide
    /* .exe\x00C:\Users\ */
    $s4 = { 00 2E 00 65 00 78 00 65 00 2E 00 43 00 3A 00 5C
    00 55 00 73 00 65 00 72 00 73 00 5C }
  condition:
    uint16(0) == 0x004c and uint32(4) == 0x00021401 and (
    filesize < 1KB and
    all of them
}