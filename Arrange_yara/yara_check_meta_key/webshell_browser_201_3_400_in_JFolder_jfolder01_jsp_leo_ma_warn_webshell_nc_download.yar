rule webshell_browser_201_3_400_in_JFolder_jfolder01_jsp_leo_ma_warn_webshell_nc_download {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell"
    family = "None"
    hacker = "None"
    hash0 = "37603e44ee6dc1c359feb68a0d566f76"
    hash1 = "a7e25b8ac605753ed0c438db93f6c498"
    hash10 = "e9a5280f77537e23da2545306f6a19ad"
    hash11 = "598eef7544935cf2139d1eada4375bb5"
    hash12 = "fa87bbd7201021c1aefee6fcc5b8e25a"
    hash2 = "fb8c6c3a69b93e5e7193036fd31a958d"
    hash3 = "36331f2c81bad763528d0ae00edf55be"
    hash4 = "793b3d0a740dbf355df3e6f68b8217a4"
    hash5 = "8979594423b68489024447474d113894"
    hash6 = "ec482fc969d182e5440521c913bab9bd"
    hash7 = "f98d2b33cd777e160d1489afed96de39"
    hash8 = "4b4c12b3002fad88ca6346a873855209"
    hash9 = "4cc68fa572e88b669bce606c7ace0ae9"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 70
    super_rule = 1
    threatname = "None"
    threattype = "None"
  strings:
    $s4 = "UplInfo info = UploadMonitor.getInfo(fi.clientFileName);" fullword
    $s5 = "long time = (System.currentTimeMillis() - starttime) / 1000l;" fullword
  condition:
    all of them
}