rule WildNeutron_Sample_6 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-07-10"
    description = "Wild Neutron APT Sample Rule - file 4bd548fe07b19178281edb1ee81c9711525dab03dc0b6676963019c44cc75865"
    family = "None"
    hacker = "None"
    hash = "4bd548fe07b19178281edb1ee81c9711525dab03dc0b6676963019c44cc75865"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://securelist.com/blog/research/71275/wild-neutron-economic-espionage-threat-actor-returns-with-new-tricks/"
    score = 60
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "mshtaex.exe" fullword wide /* score: '20.00' */
  condition:
    uint16(0) == 0x5a4d and filesize < 310KB and all of them
}