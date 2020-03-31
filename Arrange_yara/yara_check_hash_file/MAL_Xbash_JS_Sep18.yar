rule MAL_Xbash_JS_Sep18 {
  meta:
    author = Spider
    comment = None
    date = 2018-09-18
    description = Detects XBash malware
    family = Sep18
    hacker = None
    hash1 = f888dda9ca1876eba12ffb55a7a993bd1f5a622a30045a675da4955ede3e4cb8
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = https://researchcenter.paloaltonetworks.com/2018/09/unit42-xbash-combines-botnet-ransomware-coinmining-worm-targets-linux-windows/
    threatname = MAL[Xbash]/JS.Sep18
    threattype = Xbash
  strings:
    $s1 = "var path=WSHShell" fullword ascii
    $s2 = "var myObject= new ActiveXObject(" fullword ascii
    $s3 = "window.resizeTo(0,0)" fullword ascii
    $s4 = "<script language=\"JScript\">" fullword ascii /* Goodware String - occured 4 times */
  condition:
    uint16(0) == 0x483c and filesize < 5KB and
    8 of them
}