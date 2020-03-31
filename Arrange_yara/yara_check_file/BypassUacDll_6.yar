rule BypassUacDll_6 {
  meta:
    author = Spider
    comment = None
    date = None
    description = Auto-generated rule - file BypassUacDll.aps
    family = None
    hacker = None
    hash = 58d7b24b6870cb7f1ec4807d2f77dd984077e531
    judge = unknown
    reference = None
    threatname = BypassUacDll[6
    threattype = 6.yar
  strings:
    $s3 = "BypassUacDLL.dll" fullword wide
    $s4 = "AFX_IDP_COMMAND_FAILURE" fullword ascii
  condition:
    all of them
}