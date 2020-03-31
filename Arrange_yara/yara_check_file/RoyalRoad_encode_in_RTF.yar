rule RoyalRoad_encode_in_RTF {
  meta:
    author = Spider
    comment = None
    date = 2020/01/15
    description = Detects RoyalRoad weaponized RTF documents
    family = RTF
    hacker = None
    judge = unknown
    reference = https://jsac.jpcert.or.jp/archive/2020/pdf/JSAC2020_8_koike-nakajima_jp.pdf
    score = 60
    threatname = RoyalRoad[encode]/in.RTF
    threattype = encode
  strings:
    $enc_hex_1 = "B0747746"
    $enc_hex_2 = "B2A66DFF"
    $enc_hex_3 = "F2A32072"
    $enc_hex_4 = "B2A46EFF"
    $enc_hex_1l = "b0747746"
    $enc_hex_2l = "b2a66Dff"
    $enc_hex_3l = "f2a32072"
    $enc_hex_4l = "b2a46eff"
    $RTF = "{\\rt"
  condition:
    $RTF at 0 and 1 of ($enc_hex*)
}