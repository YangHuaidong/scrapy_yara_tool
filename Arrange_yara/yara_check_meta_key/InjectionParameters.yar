rule InjectionParameters {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-13"
    description = "Chinese Hacktool Set - file InjectionParameters.vb"
    family = "None"
    hacker = "None"
    hash = "4f11aa5b3660c45e527606ee33de001f4994e1ea"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "Public Shared ReadOnly Empty As New InjectionParameters(-1, \"\")" fullword ascii
    $s1 = "Public Class InjectionParameters" fullword ascii
  condition:
    filesize < 13KB and all of them
}