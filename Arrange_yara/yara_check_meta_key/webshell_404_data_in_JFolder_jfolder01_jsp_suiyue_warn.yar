rule webshell_404_data_in_JFolder_jfolder01_jsp_suiyue_warn {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - from files 404.jsp, data.jsp, in.jsp, JFolder.jsp, jfolder01.jsp, jsp.jsp, suiyue.jsp, warn.jsp"
    family = "None"
    hacker = "None"
    hash0 = "7066f4469c3ec20f4890535b5f299122"
    hash1 = "9f54aa7b43797be9bab7d094f238b4ff"
    hash2 = "793b3d0a740dbf355df3e6f68b8217a4"
    hash3 = "8979594423b68489024447474d113894"
    hash4 = "ec482fc969d182e5440521c913bab9bd"
    hash5 = "f98d2b33cd777e160d1489afed96de39"
    hash6 = "c93d5bdf5cf62fe22e299d0f2b865ea7"
    hash7 = "e9a5280f77537e23da2545306f6a19ad"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 70
    super_rule = 1
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "<table width=\"100%\" border=\"1\" cellspacing=\"0\" cellpadding=\"5\" bordercol"
    $s2 = " KB </td>" fullword
    $s3 = "<table width=\"98%\" border=\"0\" cellspacing=\"0\" cellpadding=\""
    $s4 = "<!-- <tr align=\"center\"> " fullword
  condition:
    all of them
}