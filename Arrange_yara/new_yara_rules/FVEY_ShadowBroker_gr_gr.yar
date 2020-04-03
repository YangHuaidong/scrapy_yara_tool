rule FVEY_ShadowBroker_gr_gr {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-12-17"
    description = "Auto-generated rule - file gr.notes"
    family = "None"
    hacker = "None"
    hash1 = "b2b60dce7a4cfdddbd3d3f1825f1885728956bae009de3a307342fbdeeafcb79"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/message6/"
    threatname = "None"
    threattype = "None"
  strings:
    $s4 = "delete starting from: (root) LIST (root)" fullword ascii
  condition:
    1 of them
}