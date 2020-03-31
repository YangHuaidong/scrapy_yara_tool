rule MAL_BurningUmbrella_Sample_4 {
  meta:
    author = Spider
    comment = None
    date = 2018-05-04
    description = Detects malware sample from Burning Umbrella report
    family = 4
    hacker = None
    hash1 = a1629e8abce9d670fdb66fa1ef73ad4181706eefb8adc8a9fd257b6a21be48c6
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = https://401trg.pw/burning-umbrella/
    threatname = MAL[BurningUmbrella]/Sample.4
    threattype = BurningUmbrella
  strings:
    $x1 = "dumpodbc.exe" fullword ascii
    $x2 = "photo_Bundle.exe" fullword ascii
    $x3 = "Connect 2 fails : %d,%s:%d" fullword ascii
    $x4 = "Connect fails 1 : %d %s:%d" fullword ascii
    $x5 = "New IP : %s,New Port: %d" fullword ascii
    $x6 = "Micrsoft Corporation. All rights reserved." fullword wide
    $x7 = "New ConFails : %d" fullword ascii
    $s1 = "cmd /c net stop stisvc" fullword ascii
    $s2 = "cmd /c net stop spooler" fullword ascii
    $s3 = "\\temp\\s%d.dat" fullword ascii
    $s4 = "cmd /c net stop wuauserv" fullword ascii
    $s5 = "User-Agent: MyApp/0.1" fullword ascii
    $s6 = "%s->%s Fails : %d" fullword ascii
    $s7 = "Enter WorkThread,Current sock:%d" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 50KB and (
    ( pe.exports("Print32") and 2 of them ) or
    1 of ($x*) or
    4 of them
}