rule Neuron_standalone_signature {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017/11/23"
    description = "Rule for detection of Neuron based on a standalone signature from .NET metadata"
    family = "None"
    hacker = "None"
    hash = "d1d7a96fcadc137e80ad866c838502713db9cdfe59939342b8e3beacf9c7fe29"
    judge = "black"
    reference = "https://www.ncsc.gov.uk/alerts/turla-group-malware"
    threatname = "None"
    threattype = "None"
  strings:
    $a = { eb 07 3d 15 12 31 01 12 34 08 0e 12 81 8d 1d 05 12 81 31 1d 12 81 21 1d 12 81 21 1d 12 81 21 08 1d 12 81 21 1d 12 81 21 1d 12 81 21 1d 12 81 21 1d 12 81 21 1d 12 81 21 1d 12 81 21 1d 12 81 21 1d 12 81 21 1d 12 81 21 1d 12 81 21 1d 12 81 21 1d 12 81 21 1d 12 81 21 1d 12 81 21 1d 12 81 21 1d 12 81 21 1d 12 81 21 1d 12 81 21 1d 12 81 21 1d 12 81 21 1d 12 81 21 1d 12 81 21 1d 12 81 }
    $dotnetMagic = "BSJB" ascii
  condition:
    (uint16(0) == 0x5A4D and uint16(uint32(0x3c)) == 0x4550) and all of them
}