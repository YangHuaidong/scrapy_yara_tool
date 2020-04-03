rule Txt_aspxlcx {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-14"
    description = "Chinese Hacktool Set - Webshells - file aspxlcx.txt"
    family = "None"
    hacker = "None"
    hash = "453dd3160db17d0d762e032818a5a10baf234e03"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "public string remoteip = " ascii
    $s2 = "=Dns.Resolve(host);" ascii
    $s3 = "public string remoteport = " ascii
    $s4 = "public class PortForward" ascii
  condition:
    uint16(0) == 0x253c and filesize < 18KB and all of them
}