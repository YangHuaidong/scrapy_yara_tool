rule HKTL_CN_ProcHook_May19_1 {
  meta:
    author = Spider
    comment = None
    date = 2019-05-31
    description = Detects hacktool used by Chinese threat groups
    family = May19
    hacker = None
    hash1 = 02ebdc1ff6075c15a44711ccd88be9d6d1b47607fea17bef7e5e17f8da35293e
    judge = unknown
    reference = https://www.guardicore.com/2019/05/nansh0u-campaign-hackers-arsenal-grows-stronger/
    threatname = HKTL[CN]/ProcHook.May19.1
    threattype = CN
  condition:
    uint16(0) == 0x5a4d and filesize < 300KB and
    pe.imphash() == "343d580dd50ee724746a5c28f752b709"
}