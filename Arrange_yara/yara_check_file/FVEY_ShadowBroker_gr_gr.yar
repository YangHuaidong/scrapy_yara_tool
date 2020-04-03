rule FVEY_ShadowBroker_gr_gr {
   meta:
      description = "Auto-generated rule - file gr.notes"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/message6/"
      date = "2016-12-17"
      hash1 = "b2b60dce7a4cfdddbd3d3f1825f1885728956bae009de3a307342fbdeeafcb79"
   strings:
      $s4 = "delete starting from: (root) LIST (root)" fullword ascii
   condition:
      1 of them
}