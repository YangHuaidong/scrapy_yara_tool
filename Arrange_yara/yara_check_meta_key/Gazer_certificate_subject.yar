import "pe"
rule Gazer_certificate_subject {
  meta:
    author = "Spider"
    comment = "None"
    date = "30.08.2017"
    description = "Detects Tura's Gazer malware"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "https://www.welivesecurity.com/2017/08/30/eset-research-cyberespionage-gazer/"
    threatname = "None"
    threattype = "None"
  condition:
    for any i in (0..pe.number_of_signatures - 1):
    pe.signatures[i].subject contains "Solid Loop" or
    pe.signatures[i].subject contains "Ultimate Computer Support"
}