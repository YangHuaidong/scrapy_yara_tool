import "pe"
rule MAL_BR_Report_TheDao {
  meta:
    author = "Spider"
    comment = "None"
    date = "2019-07-24"
    description = "Detects indicator in malicious UPX packed samples"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "https://github.com/br-data/2019-winnti-analyse"
    threatname = "None"
    threattype = "None"
  strings:
    $b = { da a0 }
  condition:
    uint16(0) == 0x5a4d and $b at pe.overlay.offset and pe.overlay.size > 100
}