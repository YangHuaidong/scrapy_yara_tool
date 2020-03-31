rule webshell_404_data_in_JFolder_jfolder01_xxx {
  meta:
    author = Spider
    comment = None
    date = 2014/01/28
    description = Web Shell
    family = in
    hacker = None
    hash0 = 7066f4469c3ec20f4890535b5f299122
    hash1 = 9f54aa7b43797be9bab7d094f238b4ff
    hash2 = 793b3d0a740dbf355df3e6f68b8217a4
    hash3 = 8979594423b68489024447474d113894
    hash4 = ec482fc969d182e5440521c913bab9bd
    hash5 = f98d2b33cd777e160d1489afed96de39
    hash6 = 4b4c12b3002fad88ca6346a873855209
    hash7 = c93d5bdf5cf62fe22e299d0f2b865ea7
    hash8 = e9a5280f77537e23da2545306f6a19ad
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    score = 70
    super_rule = 1
    threatname = webshell[404]/data.in.JFolder.jfolder01.xxx
    threattype = 404
  strings:
    $s4 = "&nbsp;<TEXTAREA NAME=\"cqq\" ROWS=\"20\" COLS=\"100%\"><%=sbCmd.toString()%></TE"
  condition:
    all of them
}