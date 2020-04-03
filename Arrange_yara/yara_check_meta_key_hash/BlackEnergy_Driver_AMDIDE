rule BlackEnergy_Driver_AMDIDE {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-01-04"
    description = "Black Energy Malware"
    family = "None"
    hacker = "None"
    hash1 = "32d3121135a835c3347b553b70f3c4c68eef711af02c161f007a9fbaffe7e614"
    hash2 = "3432db9cb1fb9daa2f2ac554a0a006be96040d2a7776a072a8db051d064a8be2"
    hash3 = "90ba78b6710462c2d97815e8745679942b3b296135490f0095bdc0cd97a34d9c"
    hash4 = "97be6b2cec90f655ef11ed9feef5b9ef057fd8db7dd11712ddb3702ed7c7bda1"
    hash5 = "5111de45210751c8e40441f16760bf59856ba798ba99e3c9532a104752bf7bcc"
    hash6 = "cbc4b0aaa30b967a6e29df452c5d7c2a16577cede54d6d705ca1f095bd6d4988"
    hash7 = "1ce0dfe1a6663756a32c69f7494ad082d293d32fe656d7908fb445283ab5fa68"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://www.welivesecurity.com/2016/01/03/blackenergy-sshbeardoor-details-2015-attacks-ukrainian-news-media-electric-industry/"
    super_rule = 1
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = " AMD IDE driver" fullword wide
    $s2 = "SessionEnv" fullword wide
    $s3 = "\\DosDevices\\{C9059FFF-1C49-4445-83E8-" wide
    $s4 = "\\Device\\{C9059FFF-1C49-4445-83E8-" wide
  condition:
    uint16(0) == 0x5a4d and filesize < 150KB and all of them
}