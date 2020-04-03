rule SUSP_LNK_File_PathTraversal {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-05-16"
    description = "Detects a suspicious link file that references a file multiple folders lower than the link itself"
    family = "None"
    hacker = "None"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://www.fireeye.com/blog/threat-research/2018/05/deep-dive-into-rig-exploit-kit-delivering-grobios-trojan.html"
    score = 40
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "..\\..\\..\\..\\..\\"
  condition:
    uint16(0) == 0x004c and uint32(4) == 0x00021401 and (
    filesize < 1KB and
    all of them
}