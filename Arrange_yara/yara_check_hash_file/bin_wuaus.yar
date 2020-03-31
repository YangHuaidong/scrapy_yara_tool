rule bin_wuaus {
  meta:
    author = Spider
    comment = None
    date = None
    description = Webshells Auto-generated - file wuaus.dll
    family = None
    hacker = None
    hash = 46a365992bec7377b48a2263c49e4e7d
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    threatname = bin[wuaus
    threattype = wuaus.yar
  strings:
    $s1 = "9(90989@9V9^9f9n9v9"
    $s2 = ":(:,:0:4:8:C:H:N:T:Y:_:e:o:y:"
    $s3 = ";(=@=G=O=T=X=\\="
    $s4 = "TCP Send Error!!"
    $s5 = "1\"1;1X1^1e1m1w1~1"
    $s8 = "=$=)=/=<=Y=_=j=p=z="
  condition:
    all of them
}