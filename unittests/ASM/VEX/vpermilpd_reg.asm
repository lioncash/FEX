%ifdef CONFIG
{
  "HostFeatures": ["AVX"],
  "RegData": {
    "XMM0": ["0xFFFFFFFFFFFFFFFF", "0xCCCCCCCCCCCCCCCC", "0xAAAAAAAAAAAAAAAA", "0x9999999999999999"],
    "XMM1": ["0xCCCCCCCCCCCCCCCC", "0xFFFFFFFFFFFFFFFF", "0x9999999999999999", "0xAAAAAAAAAAAAAAAA"],
    "XMM2": ["0xCCCCCCCCCCCCCCCC", "0xCCCCCCCCCCCCCCCC", "0x9999999999999999", "0x9999999999999999"],
    "XMM3": ["0xCCCCCCCCCCCCCCCC", "0xFFFFFFFFFFFFFFFF", "0x9999999999999999", "0xAAAAAAAAAAAAAAAA"],
    "XMM4": ["0xCCCCCCCCCCCCCCCC", "0xFFFFFFFFFFFFFFFF", "0x0000000000000000", "0x0000000000000000"],
    "XMM5": ["0xCCCCCCCCCCCCCCCC", "0xCCCCCCCCCCCCCCCC", "0x0000000000000000", "0x0000000000000000"],
    "XMM6": ["0xCCCCCCCCCCCCCCCC", "0xFFFFFFFFFFFFFFFF", "0x0000000000000000", "0x0000000000000000"]
  }
}
%endif

lea rdx, [rel .data]

vmovapd ymm0, [rdx]

vpermilpd ymm1, ymm0, [rel .invert]
vpermilpd ymm2, ymm0, [rel .select_elem_1]
vpermilpd ymm3, ymm0, [rel .reverse_quadwords]

vpermilpd xmm4, xmm0, [rel .invert]
vpermilpd xmm5, xmm0, [rel .select_elem_1]
vpermilpd xmm6, xmm0, [rel .reverse_quadwords]

hlt

align 32
.data:
dq 0xFFFFFFFFFFFFFFFF
dq 0xCCCCCCCCCCCCCCCC
dq 0xAAAAAAAAAAAAAAAA
dq 0x9999999999999999

.invert:
dq 0x0000000000000002
dq 0x0000000000000000
dq 0x0000000000000002
dq 0x0000000000000000

.select_elem_1:
dq 0x0000000000000002
dq 0x0000000000000002
dq 0x0000000000000002
dq 0x0000000000000002

; Upper bits filled with junk. Should have no impact on operation
.reverse_quadwords:
dq 0xFFFFFFFFFFFFFFF2
dq 0xFFFFFFFFFFFFFFF0
dq 0xFFFFFFFFFFFFFFF2
dq 0xFFFFFFFFFFFFFFF0
