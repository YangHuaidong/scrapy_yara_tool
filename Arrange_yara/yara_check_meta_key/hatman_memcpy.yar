rule hatman_memcpy : hatman {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "None"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $memcpy_be = { 7c a9 03 a6  38 84 ff ff  38 63 ff ff  8c a4 00 01
    9c a3 00 01  42 00 ff f8  4e 80 00 20              }
    $memcpy_le = { a6 03 a9 7c  ff ff 84 38  ff ff 63 38  01 00 a4 8c
    01 00 a3 9c  f8 ff 00 42  20 00 80 4e              }
  condition:
    $memcpy_be or $memcpy_le
}