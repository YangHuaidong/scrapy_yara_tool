rule WildNeutron_Sample_5 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-07-10"
    description = "Wild Neutron APT Sample Rule - file 1604e36ccef5fa221b101d7f043ad7f856b84bf1a80774aa33d91c2a9a226206"
    family = "None"
    hacker = "None"
    hash = "1604e36ccef5fa221b101d7f043ad7f856b84bf1a80774aa33d91c2a9a226206"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://securelist.com/blog/research/71275/wild-neutron-economic-espionage-threat-actor-returns-with-new-tricks/"
    score = 60
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "LiveUpdater.exe" fullword wide /* PEStudio Blacklist: strings */ /* score: '25.00' */
    $s1 = "id-at-postalAddress" fullword ascii /* PEStudio Blacklist: strings */ /* score: '18.00' */
    $s2 = "%d -> %d (default)" fullword wide /* PEStudio Blacklist: strings */ /* score: '17.00' */
    $s3 = "%s%s%s=%d,%s=%d,%s=%d," fullword wide /* score: '15.00' */
    $s4 = "sha-1WithRSAEncryption" fullword ascii /* PEStudio Blacklist: strings */ /* score: '15.00' */
    $s5 = "Postal code" fullword ascii /* PEStudio Blacklist: strings */ /* score: '14.00' */
    $s6 = "id-ce-keyUsage" fullword ascii /* score: '12.00' */
    $s7 = "Key Usage" fullword ascii /* score: '12.00' */
    $s8 = "TLS-RSA-WITH-3DES-EDE-CBC-SHA" fullword ascii /* PEStudio Blacklist: strings */ /* score: '11.00' */
    $s9 = "%02d.%04d.%s" fullword wide /* score: '7.02' */
  condition:
    uint16(0) == 0x5a4d and filesize < 1000KB and all of them
}