rule EFSO_2_asp {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file EFSO_2.asp.txt"
    family = "None"
    hacker = "None"
    hash = "b5fde9682fd63415ae211d53c6bfaa4d"
    judge = "black"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "Ejder was HERE"
    $s1 = "*~PU*&BP[_)f!8c2F*@#@&~,P~P,~P&q~8BPmS~9~~lB~X`V,_,F&*~,jcW~~[_c3TRFFzq@#@&PP,~~"
  condition:
    2 of them
}