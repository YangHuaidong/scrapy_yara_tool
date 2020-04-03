rule Duqu1_5_modules {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    desc = "Detection for Duqu 1.5 modules"
    description = "None"
    family = "None"
    hacker = "None"
    hash = "bb3961e2b473c22c3d5939adeb86819eb846ccd07f5736abb5e897918580aace"
    judge = "black"
    reference = "https://medium.com/chronicle-blog/who-is-gossipgirl-3b4170f846c0"
    threatname = "None"
    threattype = "None"
  strings:
    $c1 = "%s(%d)disk(%d)fdisk(%d)"
    $c2 = "\\Device\\Floppy%d" wide
    $c3 = "BrokenAudio" wide
    $m1 = { 81 3f e9 18 4b 7e }
    $m2 = { 81 bc 18 f8 04 00 00 b3 20 ea b4 }
  condition:
    all of them
}