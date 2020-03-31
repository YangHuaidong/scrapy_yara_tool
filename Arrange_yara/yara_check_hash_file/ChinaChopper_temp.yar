rule ChinaChopper_temp {
  meta:
    author = Spider
    comment = None
    date = 2015-06-13
    description = Chinese Hacktool Set - file temp.asp
    family = None
    hacker = None
    hash = b0561ea52331c794977d69704345717b4eb0a2a7
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = http://tools.zjqhr.com/
    threatname = ChinaChopper[temp
    threattype = temp.yar
  strings:
    $s0 = "o.run \"ff\",Server,Response,Request,Application,Session,Error" fullword ascii
    $s1 = "Set o = Server.CreateObject(\"ScriptControl\")" fullword ascii
    $s2 = "o.language = \"vbscript\"" fullword ascii
    $s3 = "o.addcode(Request(\"SC\"))" fullword ascii
  condition:
    filesize < 1KB and all of them
}