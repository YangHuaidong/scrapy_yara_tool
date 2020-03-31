rule webshell_asp_EFSO_2 {
  meta:
    author = Spider
    comment = None
    date = 2014/01/28
    description = Web Shell - file EFSO_2.asp
    family = 2
    hacker = None
    hash = a341270f9ebd01320a7490c12cb2e64c
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    score = 70
    threatname = webshell[asp]/EFSO.2
    threattype = asp
  strings:
    $s0 = "%8@#@&P~,P,PP,MV~4BP^~,NS~m~PXc3,_PWbSPU W~~[u3Fffs~/%@#@&~~,PP~~,M!PmS,4S,mBPNB"
  condition:
    all of them
}