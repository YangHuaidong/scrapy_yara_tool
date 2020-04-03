rule Nanocore_RAT_Gen_1 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-04-22"
    description = "Detetcs the Nanocore RAT and similar malware"
    family = "None"
    hacker = "None"
    hash1 = "e707a7745e346c5df59b5aa4df084574ae7c204f4fb7f924c0586ae03b79bf06"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://www.sentinelone.com/blogs/teaching-an-old-rat-new-tricks/"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "C:\\Users\\Logintech\\Dropbox\\Projects\\New folder\\Latest\\Benchmark\\Benchmark\\obj\\Release\\Benchmark.pdb" fullword ascii
    $x2 = "RunPE1" fullword ascii
    $x3 = "082B8C7D3F9105DC66A7E3267C9750CF43E9D325" fullword ascii
    $x4 = "$374e0775-e893-4e72-806c-a8d880a49ae7" fullword ascii
    $x5 = "Monitorinjection" fullword ascii
  condition:
    ( uint16(0) == 0x5a4d and filesize < 100KB and ( 1 of them ) ) or ( 3 of them )
}