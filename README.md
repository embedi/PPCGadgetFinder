# PPCGadgetFinder

An `IDAPython` script to look for ROP-gadgets for PowerPC. 

It's quite a stupid tool (it uses regular expressions for searching), but it allows you to find more useful gadgets than most of the similar utilities.

## Usage

At the `IDA Pro` command line, type:

```python
finder = PPCGadgetFinder()
finder.find('mr r3,.+')
```

Result example:

```
.....
==================================================
0xa0360 li r0, 1
0xa0364 stw r0, 0xa8(r31)
0xa0368 mr r11, r31
0xa036c mr r3, r11
0xa0370 lwz r0, 0x34(r1)
0xa0374 mtlr lr, r0
0xa0378 lwz r23, 0xc(r1)
0xa037c lwz r24, 0x10(r1)
0xa0380 lwz r25, 0x14(r1)
0xa0384 lwz r26, 0x18(r1)
0xa0388 lwz r27, 0x1c(r1)
0xa038c lwz r28, 0x20(r1)
0xa0390 lwz r29, 0x24(r1)
0xa0394 lwz r30, 0x28(r1)
0xa0398 lwz r31, 0x2c(r1)
0xa039c addi r1, r1, 0x30
==================================================
0xa0814 li r9, 0
0xa0818 mr r3, r9
0xa081c lwz r0, 0xc(r1)
0xa0820 mtlr lr, r0
0xa0824 addi r1, r1, 8
==================================================
0xcd24 mr r3, r29
0xcd28 mtlr lr, r27
==================================================
0xcde0 mr r3, r29
0xcde4 mtlr lr, r27
==================================================
0x78e70 mr r3, r31
0x78e74 mr r4, r30
0x78e78 mtlr lr, r9
==================================================
0x78f28 mr r3, r31
0x78f2c mr r4, r30
0x78f30 mtlr lr, r9
==================================================
.....
```