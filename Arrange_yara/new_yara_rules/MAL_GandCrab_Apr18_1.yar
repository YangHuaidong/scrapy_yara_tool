import "pe"

rule MAL_GandCrab_Apr18_1 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-04-23"
    description = "Detects GandCrab malware"
    family = "None"
    hacker = "None"
    hash1 = "6fafe7bb56fd2696f2243fc305fe0c38f550dffcfc5fca04f70398880570ffff"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://twitter.com/MarceloRivero/status/988455516094550017"
    threatname = "None"
    threattype = "None"
  condition:
    uint16(0) == 0x5a4d and filesize < 800KB and pe.imphash() == "7936b0e9491fd747bf2675a7ec8af8ba"
}