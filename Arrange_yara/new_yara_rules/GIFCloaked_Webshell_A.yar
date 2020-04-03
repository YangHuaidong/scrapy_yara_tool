rule GIFCloaked_Webshell_A {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Looks like a webshell cloaked as GIF"
    family = "None"
    hacker = "None"
    hash = "f1c95b13a71ca3629a0bb79601fcacf57cdfcf768806a71b26f2448f8c1d5d24"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 60
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "input type"
    $s1 = "<%eval request"
    $s2 = "<%eval(Request.Item["
    $s3 = "LANGUAGE='VBScript'"
    $s4 = "$_REQUEST" fullword
    $s5 = ";eval("
    $s6 = "base64_decode"
    $fp1 = "<form name=\"social_form\""
  condition:
    uint32(0) == 0x38464947 and ( 1 of ($s*) )
    and not 1 of ($fp*)
}