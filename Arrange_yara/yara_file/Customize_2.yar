rule Customize_2 {
    meta:
        description = "Chinese Hacktool Set - file Customize.jsp"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "37cd17543e14109d3785093e150652032a85d734"
    strings:
        $s1 = "while((l=br.readLine())!=null){sb.append(l+\"\\r\\n\");}}" fullword ascii
        $s2 = "String Z=EC(request.getParameter(Pwd)+\"\",cs);String z1=EC(request.getParameter" ascii
    condition:
        filesize < 30KB and all of them
}