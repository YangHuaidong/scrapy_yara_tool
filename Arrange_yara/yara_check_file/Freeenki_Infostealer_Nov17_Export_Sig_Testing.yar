rule Freeenki_Infostealer_Nov17_Export_Sig_Testing {
  meta:
    author = Spider
    comment = None
    date = 2017-11-28
    description = Detects Freenki infostealer malware
    family = Export
    hacker = None
    hash1 = 99c1b4887d96cb94f32b280c1039b3a7e39ad996859ffa6dd011cf3cca4f1ba5
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = http://blog.talosintelligence.com/2017/11/ROKRAT-Reloaded.html
    threatname = Freeenki[Infostealer]/Nov17.Export.Sig.Testing
    threattype = Infostealer
  condition:
    uint16(0) == 0x5a4d and filesize < 3000KB and
    pe.exports("getUpdate") and pe.number_of_exports == 1
}