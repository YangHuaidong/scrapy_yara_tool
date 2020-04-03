rule genhash_genhash {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-07-10"
    description = "Auto-generated rule - file genhash.exe"
    family = "None"
    hacker = "None"
    hash = "113df11063f8634f0d2a28e0b0e3c2b1f952ef95bad217fd46abff189be5373f"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://www.coresecurity.com/corelabs-research/open-source-tools/pass-hash-toolkit"
    score = 80
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "genhash.exe <password>" fullword ascii /* PEStudio Blacklist: strings */ /* score: '30.00' */
    $s3 = "Password: %s" fullword ascii /* PEStudio Blacklist: strings */ /* score: '17.00' */
    $s4 = "%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X" fullword ascii /* score: '11.00' */
    $s5 = "This tool generates LM and NT hashes." fullword ascii /* score: '10.00' */
    $s6 = "(hashes format: LM Hash:NT hash)" fullword ascii /* score: '10.00' */
  condition:
    uint16(0) == 0x5a4d and filesize < 200KB and 2 of them
}