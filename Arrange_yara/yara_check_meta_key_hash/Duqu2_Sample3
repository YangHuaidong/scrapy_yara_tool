rule Duqu2_Sample3 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-07-02"
    description = "Detects Duqu2 Malware"
    family = "None"
    hacker = "None"
    hash1 = "2a9a5afc342cde12c6eb9a91ad29f7afdfd8f0fb17b983dcfddceccfbc17af69"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://securelist.com/blog/research/70504/the-mystery-of-duqu-2-0-a-sophisticated-cyberespionage-actor-returns/"
    score = 80
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "SELECT `%s` FROM `%s` WHERE `%s`='CAData%i'" fullword wide
  condition:
    ( uint16(0) == 0x5a4d and filesize < 50KB and $s1 )
}