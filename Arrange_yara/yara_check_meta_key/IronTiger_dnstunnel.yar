rule IronTiger_dnstunnel {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "This rule detects a dns tunnel tool used in Operation Iron Tiger"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "http://goo.gl/T5fSJC"
    threatname = "None"
    threattype = "None"
  strings:
    $str1 = "\\DnsTunClient\\" nocase wide ascii
    $str2 = "\\t-DNSTunnel\\" nocase wide ascii
    $str3 = "xssok.blogspot" nocase wide ascii
    $str4 = "dnstunclient" nocase wide ascii
    $mistake1 = "because of error, can not analysis" nocase wide ascii
    $mistake2 = "can not deal witn the error" nocase wide ascii
    $mistake3 = "the other retun one RST" nocase wide ascii
    $mistake4 = "Coversation produce one error" nocase wide ascii
    $mistake5 = "Program try to use the have deleted the buffer" nocase wide ascii
  condition:
    (uint16(0) == 0x5a4d) and ((any of ($str*)) or (any of ($mistake*)))
}