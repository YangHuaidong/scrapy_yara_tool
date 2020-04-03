rule SVG_LoadURL {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-05-24"
    description = "Detects a tiny SVG file that loads an URL (as seen in CryptoWall malware infections)"
    family = "None"
    hacker = "None"
    hash1 = "ac8ef9df208f624be9c7e7804de55318"
    hash2 = "3b9e67a38569ebe8202ac90ad60c52e0"
    hash3 = "7e2be5cc785ef7711282cea8980b9fee"
    hash4 = "4e2c6f6b3907ec882596024e55c2b58b"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://goo.gl/psjCCc"
    score = 50
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "</svg>" nocase
    $s2 = "<script>" nocase
    $s3 = "location.href='http" nocase
  condition:
    all of ($s*) and filesize < 600
}