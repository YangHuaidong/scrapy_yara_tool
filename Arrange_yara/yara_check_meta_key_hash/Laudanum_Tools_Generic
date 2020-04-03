rule Laudanum_Tools_Generic {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-22"
    description = "Laudanum Injector Tools"
    family = "None"
    hacker = "None"
    hash0 = "076aa781a004ecb2bf545357fd36dcbafdd68b1a"
    hash1 = "885e1783b07c73e7d47d3283be303c9719419b92"
    hash10 = "5570d10244d90ef53b74e2ac287fc657e38200f0"
    hash11 = "42bcb491a11b4703c125daf1747cf2a40a1b36f3"
    hash12 = "83e4eaaa2cf6898d7f83ab80158b64b1d48096f4"
    hash13 = "dec7ea322898690a7f91db9377f035ad7072b8d7"
    hash14 = "a2272b8a4221c6cc373915f0cc555fe55d65ac4d"
    hash15 = "588739b9e4ef2dbb0b4cf630b73295d8134cc801"
    hash16 = "43320dc23fb2ed26b882512e7c0bfdc64e2c1849"
    hash2 = "01d5d16d876c55d77e094ce2b9c237de43b21a16"
    hash3 = "7421d33e8007c92c8642a36cba7351c7f95a4335"
    hash4 = "f49291aef9165ee4904d2d8c3cf5a6515ca0794f"
    hash5 = "c0dee56ee68719d5ec39e773621ffe40b144fda5"
    hash6 = "f32b9c2cc3a61fa326e9caebce28ef94a7a00c9a"
    hash7 = "dc5c03a21267d024ef0f5ab96a34e3f6423dfcd6"
    hash8 = "fd498c8b195967db01f68776ff5e36a06c9dfbfe"
    hash9 = "b50ae35fcf767466f6ca25984cc008b7629676b8"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://laudanum.inguardians.com/"
    super_rule = 1
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "***  laudanum@secureideas.net" fullword ascii
    $s2 = "*** Laudanum Project" fullword ascii
  condition:
    filesize < 60KB and all of them
}