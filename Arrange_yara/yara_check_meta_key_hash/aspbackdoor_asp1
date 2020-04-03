rule aspbackdoor_asp1 {
  meta:
    author = "Spider"
    comment = "None"
    date = "23.11.14"
    description = "Disclosed hacktool set (old stuff) - file asp1.txt"
    family = "None"
    hacker = "None"
    hash = "9ef9f34392a673c64525fcd56449a9fb1d1f3c50"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 60
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "param = \"driver={Microsoft Access Driver (*.mdb)}\" " fullword ascii
    $s1 = "conn.Open param & \";dbq=\" & Server.MapPath(\"scjh.mdb\") " fullword ascii
    $s6 = "set rs=conn.execute (sql)%> " fullword ascii
    $s7 = "<%set Conn = Server.CreateObject(\"ADODB.Connection\") " fullword ascii
    $s10 = "<%dim ktdh,scph,scts,jhqtsj,yhxdsj,yxj,rwbh " fullword ascii
    $s15 = "sql=\"select * from scjh\" " fullword ascii
  condition:
    all of them
}