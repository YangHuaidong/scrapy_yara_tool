rule EQGRP_1212 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-08-15"
    description = "Detects tool from EQGRP toolset - file 1212.pl"
    family = "None"
    hacker = "None"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Research"
    score = 75
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "if (!(($srcip,$dstip,$srcport,$dstport) = ($line=~/^([a-f0-9]{8})([a-f0-9]{8})([a-f0-9]{4})([a-f0-9]{4})$/)))" fullword ascii
    $s2 = "$ans=\"$srcip:$srcport -> $dstip:$dstport\";" fullword ascii
    $s3 = "return \"ERROR:$line is not a valid port\";" fullword ascii
    $s4 = "$dstport=hextoPort($dstport);" fullword ascii
    $s5 = "sub hextoPort" fullword ascii
    $s6 = "$byte_table{\"$chars[$sixteens]$chars[$ones]\"}=$i;" fullword ascii
  condition:
    filesize < 6KB and 4 of them
}