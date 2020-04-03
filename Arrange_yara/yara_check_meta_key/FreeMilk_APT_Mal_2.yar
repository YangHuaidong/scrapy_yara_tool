import "pe"

  meta:
    author = "Spider"
    comment = "None"
    date = "2017-10-05"
    description = "Detects malware from FreeMilk campaign"
    family = "None"
    hacker = "None"
    hash1 = "7f35521cdbaa4e86143656ff9c52cef8d1e5e5f8245860c205364138f82c54df"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://researchcenter.paloaltonetworks.com/2017/10/unit42-freemilk-highly-targeted-spear-phishing-campaign/"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "failed to take the screenshot. err: %d" fullword ascii
    $s2 = "runsample" fullword wide
    $s3 = "%s%02X%02X%02X%02X%02X%02X:" fullword wide
    $s4 = "win-%d.%d.%d-%d" fullword wide
  condition:
    uint16(0) == 0x5a4d and filesize < 400KB and (
    pe.imphash() == "b86f7d2c1c182ec4c074ae1e16b7a3f5" or
    all of them
}