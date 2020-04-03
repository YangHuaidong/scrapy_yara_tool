rule APT_MAL_CN_Wocao_agent_py_b64encoded {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Piece of Base64 encoded data from Agent Python version"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "https://www.fox-it.com/en/news/whitepapers/operation-wocao-shining-a-light-on-one-of-chinas-hidden-hacking-groups/"
    threatname = "None"
    threattype = "None"
  strings:
    $header = "QlpoOTFBWSZTWWDdHjgABDTfgHwQe////z/v/9+////6YA4cGPsAl2e8M9LSU128"
  condition:
    all of them
}