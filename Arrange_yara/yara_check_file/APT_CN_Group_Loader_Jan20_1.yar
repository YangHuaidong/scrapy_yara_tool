rule APT_CN_Group_Loader_Jan20_1 {
  meta:
    author = Spider
    comment = None
    date = 2020-02-01
    description = Detects loaders used by Chinese groups
    family = Loader
    hacker = None
    judge = unknown
    reference = https://twitter.com/VK_Intel/status/1223411369367785472?s=20
    score = 80
    threatname = APT[CN]/Group.Loader.Jan20.1
    threattype = CN
  strings:
    $xc1 = { 8b c3 c1 e3 10 c1 e8 10 03 d8 6b db 77 83 c3 13 }
  condition:
    1 of them
}