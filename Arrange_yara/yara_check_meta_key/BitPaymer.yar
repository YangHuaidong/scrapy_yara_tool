rule BitPaymer {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Rule to detect newer Bitpaymer samples. Rule is based on BitPaymer custom packer"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "None"
    refrence = "http://blog.morphisec.com/bitpaymer-ransomware-with-new-custom-packer-framework"
    threatname = "None"
    threattype = "None"
  strings:
    $opcodes1 = {B9 ?? 00 00 00 FF 14 0F B8 FF 00 00 00 C3 89 45 FC}
    $opcodes2 = { 61 55 ff 54 b7 01 b0 ff c9 c3 cc 89 45 fc }
  condition:
    (uint16 (0) == 0x5a4d) and ($opcodes1 or $opcodes2)
}