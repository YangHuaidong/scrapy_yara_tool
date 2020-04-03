rule SUSP_DropperBackdoor_Keywords {
  meta:
    author = "Spider"
    comment = "None"
    date = "2019-04-24"
    description = "Detects suspicious keywords that indicate a backdoor"
    family = "None"
    hacker = "None"
    hash1 = "cd4b9d0f2d1c0468750855f0ed352c1ed6d4f512d66e0e44ce308688235295b5"
    judge = "black"
    reference = "https://blog.talosintelligence.com/2019/04/dnspionage-brings-out-karkoff.html"
    threatname = "None"
    threattype = "None"
  strings:
    $x4 = "DropperBackdoor" fullword wide ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 1000KB and 1 of them
}