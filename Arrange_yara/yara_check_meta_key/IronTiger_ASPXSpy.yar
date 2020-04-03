rule IronTiger_ASPXSpy {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "ASPXSpy detection. It might be used by other fraudsters"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "http://goo.gl/T5fSJC"
    threatname = "None"
    threattype = "None"
  strings:
    $str2 = "IIS Spy" wide ascii
    $str3 = "protected void DGCoW(object sender,EventArgs e)" nocase wide ascii
  condition:
    any of ($str*)
}