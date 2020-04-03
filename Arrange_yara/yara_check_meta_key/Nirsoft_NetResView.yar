rule Nirsoft_NetResView {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-06-04"
    description = "Detects NirSoft NetResView - utility that displays the list of all network resources"
    family = "None"
    hacker = "None"
    hash1 = "83f0352c14fa62ae159ab532d85a2b481900fed50d32cc757aa3f4ccf6a13bee"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://goo.gl/Mr6M2J"
    score = 40
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "NetResView.exe" fullword wide
    $s2 = "2005 - 2013 Nir Sofer" wide
  condition:
    uint16(0) == 0x5a4d and filesize < 100KB and all of them
}