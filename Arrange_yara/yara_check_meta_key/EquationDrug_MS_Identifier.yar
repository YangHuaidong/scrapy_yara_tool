import "pe"
rule EquationDrug_MS_Identifier {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015/03/11"
    description = "Microsoft Identifier used in EquationDrug Platform"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "Microsoft(R) Windows (TM) Operating System" fullword wide
  condition:
    $s1 and pe.timestamp > 946684800
}