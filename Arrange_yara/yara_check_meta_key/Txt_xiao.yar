rule Txt_xiao {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-14"
    description = "Chinese Hacktool Set - Webshells - file xiao.txt"
    family = "None"
    hacker = "None"
    hash = "b3b98fb57f5f5ccdc42e746e32950834807903b7"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "Session.Contents.Remove(m & \"userPassword\")" fullword ascii
    $s2 = "passWord = Encode(GetPost(\"password\"))" fullword ascii
    $s3 = "conn.Execute(\"Create Table FileData(Id int IDENTITY(0,1) PRIMARY KEY CLUSTERED," ascii
    $s4 = "function Command(cmd, str){" fullword ascii
    $s5 = "echo \"if(obj.value=='PageWebProxy')obj.form.target='_blank';\"" fullword ascii
  condition:
    filesize < 100KB and all of them
}