rule malrtf_ole2link : exploit {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Detect weaponized RTF documents with OLE2Link exploit"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $rtf_olelink_01 = "\\objdata" nocase
    $rtf_olelink_02 = "4f4c45324c696e6b" nocase
    $rtf_olelink_03 = "d0cf11e0a1b11ae1" nocase
    $rtf_payload_01 = "68007400740070003a002f002f00" nocase
    $rtf_payload_02 = "680074007400700073003a002f002f00" nocase
    $rtf_payload_03 = "6600740070003a002f002f00" nocase
  condition:
    uint32be(0) == 0x7B5C7274
    and all of ($rtf_olelink_*)
    and any of ($rtf_payload_*)
}