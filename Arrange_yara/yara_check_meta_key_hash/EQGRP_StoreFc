rule EQGRP_StoreFc {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-08-16"
    description = "EQGRP Toolset Firewall - file StoreFc.py"
    family = "None"
    hacker = "None"
    hash1 = "f155cce4eecff8598243a721389046ae2b6ca8ba6cb7b4ac00fd724601a56108"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Research"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "Usage: StoreFc.py --configFile=<path to xml file> --implantFile=<path to BinStore implant> [--outputFile=<file to write the conf" ascii
    $x2 = "raise Exception, \"Must supply both a config file and implant file.\"" fullword ascii
    $x3 = "This is wrapper for Store.py that FELONYCROWBAR will use. This" fullword ascii
  condition:
    1 of them
}