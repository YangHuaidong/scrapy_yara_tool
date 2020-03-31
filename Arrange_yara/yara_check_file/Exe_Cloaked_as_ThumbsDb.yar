rule Exe_Cloaked_as_ThumbsDb {
  meta:
    author = Spider
    comment = None
    date = 2014-07-18
    description = Detects an executable cloaked as thumbs.db - Malware
    family = ThumbsDb
    hacker = None
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    score = 50
    threatname = Exe[Cloaked]/as.ThumbsDb
    threattype = Cloaked
  condition:
    uint16(0) == 0x5a4d and filename matches /[Tt]humbs\.db/
}