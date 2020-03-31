rule Xtreme_RAT_Gen_Imp {
  meta:
    author = Spider
    comment = None
    date = 2017-09-27
    description = Detects XTREME sample analyzed in September 2017
    family = Imp
    hacker = None
    hash1 = 7b5082bcc8487bb65c38e34c192c2a891e7bb86ba97281352b0837debee6f1cf
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = Internal Research
    threatname = Xtreme[RAT]/Gen.Imp
    threattype = RAT
  condition:
    uint16(0) == 0x5a4d and filesize < 300KB and (
    pe.imphash() == "d0bdf112886f3d846cc7780967d8efb9" or
    pe.imphash() == "cc6f630f214cf890e63e899d8ebabba6" or
    pe.imphash() == "e0f7991d50ceee521d7190effa3c494e"
}