import re

from idc import FindBinary, SEARCH_CASE, SEARCH_DOWN, BADADDR
from idc import PrevHead, GetMnem, GetOperandValue, GetOpnd, GetOpType, o_displ
from idaapi import get_segm_qty, getnseg, SEG_CODE, BADADDR
from idaapi import is_indirect_jump_insn


class PPCInstruction(object):
    def __init__(self, ea=BADADDR):
        self.ea = ea
        self.mnem = GetMnem(ea)
        self.operands = self._normalize_operands(self.ea)

    @staticmethod
    def _normalize_operands(ea):
        ops = [None, None, None]
        for i in range(3):
            if GetOpType(ea, i) == o_displ:
                op = GetOpnd(ea, i)
                try:
                    ops[i] = '0x%x%s' % (GetOperandValue(ea, i), op[op.index('('):])
                except:
                    ops[i] = ''
            else:
                ops[i] = GetOpnd(ea, i)
        return ops

    def __str__(self):
        if self.operands is not None:
            return self.mnem + ' ' + ', '.join([op for op in self.operands if op != ''])
        else:
            return ''


class PPCGadgetFinder(object):
    BCTR = '4E 80 04 20'
    BLR = '4E 80 00 20'
    BCTRL = '4E 80 04 21'
    BLRL = '4E 80 00 21'

    def __init__(self, depth=25):
        self.control_braches = list()
        self.startEA, self.endEA = self._get_code_segment()
        self.depth = depth

        self._find_control_branches()

    @staticmethod
    def _get_code_segment():
        for i in xrange(get_segm_qty()):
            seg = getnseg(i)
            if seg is not None:
                if seg.type == SEG_CODE:
                    return seg.startEA, seg.endEA
        return None, None

    def _find_binary(self, pattern=None, ins_size=4):
        cursor = self.startEA
        while True:
            cursor = FindBinary(cursor, SEARCH_CASE | SEARCH_DOWN, pattern, 16)
            if cursor == BADADDR:
                raise StopIteration
            yield cursor
            cursor += ins_size

    def _find_control_branches(self):
        for ctrl_branch in self._find_binary(pattern=PPCGadgetFinder.BLR):
            self.control_braches.append((ctrl_branch, list()))
        for ctrl_branch in self._find_binary(pattern=PPCGadgetFinder.BCTR):
            self.control_braches.append((ctrl_branch, list()))
        for ctrl_branch in self._find_binary(pattern=PPCGadgetFinder.BLRL):
            self.control_braches.append((ctrl_branch, list()))
        for ctrl_branch in self._find_binary(pattern=PPCGadgetFinder.BCTRL):
            self.control_braches.append((ctrl_branch, list()))

    def _get_prev_instructions(self, ea, prev_instructions):
        count, cursor = 0, PrevHead(ea)
        while count < self.depth and not is_indirect_jump_insn(cursor) and cursor != BADADDR:
            prev_instructions.append(PPCInstruction(cursor))
            cursor = PrevHead(cursor)
            count += 1

    def find(self, regexp=None):
        gadgets = list()
        for branch, prev_instructions in self.control_braches:
            if len(prev_instructions) == 0:
                self._get_prev_instructions(branch, prev_instructions)
            for ins in prev_instructions:
                if re.match(regexp, str(ins)) is not None:
                    gadgets.append((branch, prev_instructions))

        for g, prev_insns in gadgets:
            for ins in reversed(prev_insns):
                print '0x%x %s' % (ins.ea, ins)
            print '=' * 50
