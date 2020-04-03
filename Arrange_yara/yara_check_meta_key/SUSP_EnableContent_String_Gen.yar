rule SUSP_EnableContent_String_Gen {
  meta:
    author = "Spider"
    comment = "None"
    date = "2019-02-12"
    description = "Detects suspicious string that asks to enable active content in Office Doc"
    family = "None"
    hacker = "None"
    hash1 = "525ba2c8d35f6972ac8fcec8081ae35f6fe8119500be20a4113900fe57d6a0de"
    judge = "black"
    reference = "Internal Research"
    threatname = "None"
    threattype = "None"
  strings:
    $e1 = "Enable Editing" fullword ascii
    $e2 = "Enable Content" fullword ascii
    $e3 = "Enable editing" fullword ascii
    $e4 = "Enable content" fullword ascii
  condition:
    uint16(0) == 0xcfd0 and (
    $e1 in (0..3000) or
    $e2 in (0..3000) or
    $e3 in (0..3000) or
    $e4 in (0..3000) or
    2 of them
}