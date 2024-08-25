#!/usr/bin/env python3

from bs4 import BeautifulSoup
from bs4.formatter import XMLFormatter
from collections import OrderedDict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List
import ipdb
import json
import logging
import os
import re
import subprocess
import sys


logging.basicConfig(
    # Uncomment for trace logging
    # level=logging.DEBUG,
    level=logging.INFO,
    format="\033[35;1m[%(funcName)s():%(lineno)s]\033[1;0m %(message)s",
)


class UnsortedAttributes(XMLFormatter):
    def attributes(self, tag):
        for k, v in tag.attrs.items():
            yield k, v


"""
Lexer
"""


@dataclass
class TokWhitespace:
    def __str__(self):
        return " "


@dataclass
class TokLiteral:
    data: str


@dataclass
class TokDelimiter:
    data: str


@dataclass
class TokHex:
    data: str


@dataclass
class TokDec:
    data: str


@dataclass
class TokAdd:
    def __str__(self):
        return "+"


@dataclass
class TokMul:
    def __str__(self):
        return "*"


@dataclass
class TokVar:
    data: str


@dataclass
class TokReg(TokVar):
    pass


@dataclass
class TokP(TokVar):
    pass


@dataclass
class TokQ(TokVar):
    pass


@dataclass
class TokS8(TokVar):
    pass


@dataclass
class TokU4(TokVar):
    pass


@dataclass
class TokU8(TokVar):
    pass


@dataclass
class TokU16(TokVar):
    pass


asm_patterns = [
    (r"nn[ n]*", lambda s, t: TokU16(t)),
    (r"n", lambda s, t: TokU8(t)),
    (r"b", lambda s, t: TokU4(t)),
    (r"o", lambda s, t: TokS8(t)),
    (r"r", lambda s, t: TokReg(t)),
    (r"p", lambda s, t: TokP(t)),
    (r"q", lambda s, t: TokQ(t)),
    (r"[a-zA-Z0-9][a-zA-Z0-9]", lambda s, t: TokHex(t)),
    (r"^[0-9]$", lambda s, t: TokHex(t)),
    (r"[0-9]", lambda s, t: TokDec(t)),
    (r"[+]", lambda s, t: TokAdd()),
    (r"[*]", lambda s, t: TokMul()),
    (r"[" " \\n]+", lambda s, t: TokWhitespace()),
]


disasm_patterns = [
    (r"nn[ n]*", lambda s, t: TokU16(t)),
    (r"n", lambda s, t: TokU8(t)),
    (r"b", lambda s, t: TokU4(t)),
    (r"o", lambda s, t: TokS8(t)),
    (r"r", lambda s, t: TokReg(t)),
    (r"p", lambda s, t: TokP(t)),
    (r"q", lambda s, t: TokQ(t)),
    (r"[a-zA-Z0-9][a-zA-Z0-9']*", lambda s, t: TokLiteral(t)),
    (r"[\+\*,() \\n]", lambda s, t: TokDelimiter(t)),
]


def disasm_tokenize(disasm):
    acceptable = re.Scanner(disasm_patterns)
    matched, unk = acceptable.scan(disasm)
    if unk:
        raise RuntimeError(f'Unknown token: "{unk}".')
    return matched


def asm_tokenize(asm):
    acceptable = re.Scanner(asm_patterns)
    matched, unk = acceptable.scan(asm)
    if unk:
        raise RuntimeError(f'Unknown token: "{unk}".')
    return matched


"""
Parser
"""


@dataclass
class RuleCounter:
    n: int
    i: int = field(default=0)
    is_name_output: bool = field(default=False)
    is_reg: bool = field(default=False)
    is_signed: bool = field(default=False)

    def reset(self):
        self.i = 0

    def next(self):
        if self.i >= self.n:
            return None
        next_i = self.i
        self.i += 1
        return next_i


@dataclass
class RuleCounterOptions(RuleCounter):
    n: int = field(default=0)
    i: int = field(default=0)
    options: dict = field(default_factory=lambda: {})

    def next(self):
        while self.i not in self.options.keys():
            if self.i >= self.n:
                return None
            self.i += 1
        next_i = self.i
        self.i += 1
        return self.options[next_i] if self.is_name_output else next_i


@dataclass
class RuleCounterBit(RuleCounterOptions):
    n: int = field(default=8)
    i: int = field(default=0)
    is_reg: bool = field(default=True)
    options: dict = field(
        default_factory=lambda: {
            0: "0",
            1: "1",
            2: "2",
            3: "3",
            4: "4",
            5: "5",
            6: "6",
            7: "7",
        }
    )


@dataclass
class RuleCounterReg(RuleCounterOptions):
    n: int = field(default=8)
    i: int = field(default=0)
    is_reg: bool = field(default=True)
    options: dict = field(
        default_factory=lambda: {
            0: "B",
            1: "C",
            2: "D",
            3: "E",
            4: "H",
            5: "L",
            7: "A",
        }
    )


@dataclass
class RuleCounterP(RuleCounterReg):
    options: dict = field(
        default_factory=lambda: {
            0: "B",
            1: "C",
            2: "D",
            3: "E",
            4: "IXh",
            5: "IXl",
            7: "A",
        }
    )


@dataclass
class RuleCounterQ(RuleCounterReg):
    options: dict = field(
        default_factory=lambda: {
            0: "B",
            1: "C",
            2: "D",
            3: "E",
            4: "IYh",
            5: "IYl",
            7: "A",
        }
    )


@dataclass
class RuleSplittable:
    pass


@dataclass
class RuleLiteral(RuleSplittable):
    data: str
    is_offset: bool = field(default=False)
    is_signed: bool = field(default=False)
    var_names: List = field(default_factory=list)
    split_i: int = field(default=0)
    seq_i: int = field(default=0)

    def eval(self, ctx=None):
        return self.data

    def __str__(self):
        return self.data


@dataclass
class RuleHex(RuleSplittable):
    data: int
    is_offset: bool = field(default=False)
    is_signed: bool = field(default=False)
    var_names: List = field(default_factory=list)
    split_i: int = field(default=0)
    seq_i: int = field(default=0)

    def eval(self, ctx=None):
        return self.data

    def glyph_str(self):
        return f"{self.data:02x}"

    def __str__(self):
        return self.glyph_str()


@dataclass
class RuleVarRef(RuleSplittable):
    name: str
    split_i: int = field(default=0)
    seq_i: int = field(default=0)

    def eval(self, ctx):
        return ctx[name].eval(ctx)


@dataclass
class RuleVar:
    name: str
    counter: RuleCounter

    def eval(self, ctx=None):
        return counter.next()


@dataclass
class RuleExpr:
    lhs: Any
    op: str
    rhs: Any

    def eval(self, arg, ctx):
        if isinstance(arg, (RuleExpr, RuleHex, RuleVar)):
            return arg.eval(ctx)
        return arg

    def eval(self, ctx):
        if isinstance(self.op, TokAdd):
            op_func = lambda x, y: x + y
        elif isinstance(self.op, TokMul):
            op_func = lambda x, y: x * y
        else:
            raise RuntimeError(f'Unknown expr op: "{self.op}".')
        return op_func(self.lhs.eval(ctx), self.rhs.eval(ctx))


@dataclass
class RuleEnd(RuleSplittable):
    split_i: int = field(default=99999)
    seq_i: int = field(default=99999)


@dataclass
class Parser:
    variables: Dict = field(default_factory=dict)
    rules: List = field(default_factory=list)
    tokens: List = field(default_factory=list)
    tok_i: int = field(default=0)

    def normalize_name(self, name):
        return name.replace("nn nn", "nn")

    def advance(self):
        if self.tok_i >= len(self.tokens):
            return None

        next_token = self.tokens[self.tok_i]
        self.tok_i += 1
        return next_token

    def peek(self, k=0):
        if (self.tok_i + k) >= len(self.tokens):
            return None

        return self.tokens[self.tok_i + k]

    def accept(self, expected):
        next_token = self.advance()
        if next_token is None:
            return None

        if isinstance(next_token, expected):
            return next_token
        else:
            raise RuntimeError(
                f'Unexpected token "{next_token}". Expected "{expected}".'
            )

    def parse(self):
        pass


@dataclass
class AsmParser(Parser):
    def rule_operand(self, resolved):
        k = resolved.data
        if isinstance(resolved, TokDec):
            return RuleHex(int(resolved.data, 10))
        elif isinstance(resolved, TokHex):
            return RuleHex(int(resolved.data, 16))
        elif isinstance(resolved, TokVar):
            tok_name = self.normalize_name(resolved.data)
            if isinstance(resolved, TokU16):
                counter = RuleCounter(256 * 256)
            elif isinstance(resolved, TokU8):
                counter = RuleCounter(256)
            elif isinstance(resolved, TokS8):
                counter = RuleCounter(256, is_signed=True)
            elif isinstance(resolved, TokU4):
                counter = RuleCounterBit()
            elif isinstance(resolved, TokReg):
                counter = RuleCounterReg()
            elif isinstance(resolved, TokP):
                counter = RuleCounterP()
            elif isinstance(resolved, TokQ):
                counter = RuleCounterQ()
            else:
                raise RuntimeError(f'Unknown var tok: "{tok_name}".')
            self.variables[tok_name] = RuleVar(tok_name, counter)
            return RuleVarRef(tok_name)
        else:
            raise RuntimeError(f'Unknown tok: "{resolved}".')
        return k

    def rule_binop(self, lhs):
        next_type = (TokAdd, TokMul, type(None))
        op = self.accept(next_type)
        if isinstance(op, type(None)):
            return lhs
        elif isinstance(op, TokAdd):
            rhs = self.rule_operand(self.accept((TokDec, TokHex, TokVar)))
            next_op = self.peek()
            if isinstance(next_op, (TokAdd, TokMul)):
                return RuleExpr(lhs, op, self.rule_binop(rhs))
            return RuleExpr(lhs, op, rhs)
        elif isinstance(op, TokMul):
            rhs = self.rule_operand(self.accept((TokDec, TokHex, TokVar)))
            expr = RuleExpr(lhs, op, rhs)
            next_op = self.peek()
            next_lhs = self.peek(1)
            if isinstance(next_op, (TokAdd, TokMul)) and isinstance(
                next_lhs, (TokHex, TokVar)
            ):
                return self.rule_binop(expr)
            return expr

    def parse(self):
        next_type = (TokHex, TokVar)
        while self.peek():
            resolved = self.accept(next_type)
            if isinstance(resolved, (TokDec, TokHex)):
                k = self.rule_operand(resolved)
                if isinstance(self.peek(), (TokAdd, TokMul)):
                    self.rules.append(self.rule_binop(k))
                else:
                    self.rules.append(k)

                next_type = (TokWhitespace, type(None))
            elif isinstance(resolved, TokWhitespace):
                # Irrelevant
                next_type = (TokHex, TokVar, type(None))
            elif isinstance(resolved, TokVar):
                tok_name = self.normalize_name(resolved.data)
                if isinstance(resolved, TokU16):
                    counter = RuleCounter(256 * 256)
                elif isinstance(resolved, TokU8):
                    counter = RuleCounter(256)
                elif isinstance(resolved, TokS8):
                    counter = RuleCounter(256, is_signed=True)
                elif isinstance(resolved, TokU4):
                    counter = RuleCounterBit()
                elif isinstance(resolved, TokReg):
                    counter = RuleCounterReg()
                elif isinstance(resolved, TokP):
                    counter = RuleCounterP()
                elif isinstance(resolved, TokQ):
                    counter = RuleCounterQ()
                else:
                    raise RuntimeError(f'Unknown var tok: "{tok_name}".')
                self.rules.append(RuleVarRef(tok_name))
                self.variables[tok_name] = RuleVar(tok_name, counter)
                next_type = (TokWhitespace, type(None))
            else:
                raise RuntimeError(f'Unknown tok: "{resolved}".')
        self.rules.append(RuleEnd())


@dataclass
class DisasmParser(Parser):
    def parse(self):
        next_type = TokLiteral
        while self.peek():
            resolved = self.accept(next_type)
            if isinstance(resolved, TokLiteral):
                self.rules.append(RuleLiteral(resolved.data))
                next_type = (TokLiteral, TokDelimiter, TokVar, type(None))
            elif isinstance(resolved, TokDelimiter):
                self.rules.append(RuleLiteral(resolved.data))
                next_type = (TokLiteral, TokDelimiter, TokVar, type(None))
            elif isinstance(resolved, TokVar):
                tok_name = self.normalize_name(resolved.data)
                if isinstance(resolved, TokU16):
                    counter = RuleCounter(256 * 256)
                elif isinstance(resolved, TokU8):
                    counter = RuleCounter(256)
                elif isinstance(resolved, TokS8):
                    counter = RuleCounter(256, is_signed=True)
                elif isinstance(resolved, TokU4):
                    counter = RuleCounterBit(is_name_output=True)
                elif isinstance(resolved, TokReg):
                    counter = RuleCounterReg(is_name_output=True)
                elif isinstance(resolved, TokP):
                    counter = RuleCounterP(is_name_output=True)
                elif isinstance(resolved, TokQ):
                    counter = RuleCounterQ(is_name_output=True)
                else:
                    raise RuntimeError(f'Unknown var tok: "{tok_name}".')
                self.rules.append(RuleVarRef(tok_name))
                self.variables[tok_name] = RuleVar(tok_name, counter)
        self.rules.append(RuleEnd())


"""
Generator
"""


@dataclass
class EmitGlyph:
    name: str
    asms: List = field(default_factory=list)
    lookup_i: int = field(default=0)
    is_offset: bool = field(default=False)


@dataclass
class EmitLookup:
    pass


@dataclass
class EmitLookupLigatureSubst(EmitLookup):
    ligature_set_glyphs: Dict = field(default_factory=dict)


@dataclass
class EmitLookupMultipleSubst(EmitLookup):
    in_glyphs: Dict = field(default_factory=dict)


@dataclass
class Generator:
    def generate(self, data):
        all_disasm_emitted = []
        all_asm_emitted = []
        for d in data:
            disasm = d[0]
            asm = d[1]
            disasm_tokens = disasm_tokenize(disasm)
            asm_tokens = asm_tokenize(asm)
            logging.debug(f"{disasm}=>{disasm_tokens} | {asm}=>{asm_tokens}")

            disasm_parser = DisasmParser(tokens=disasm_tokens)
            disasm_parser.parse()
            logging.debug("".join(str(x) for x in disasm_parser.rules))
            logging.debug(disasm_parser.variables)

            asm_parser = AsmParser(tokens=asm_tokens)
            asm_parser.parse()
            logging.debug("".join(str(x) for x in asm_parser.rules))
            logging.debug(asm_parser.variables)

            # First expand assembly encoding, since vars will have the order for disassembly splits
            asm_gen = ExpandGenerator(asm_parser.variables, asm_parser.rules)
            asm_emitted = asm_gen.generate()
            all_asm_emitted.extend(asm_emitted)
            logging.debug(asm_emitted)

            disasm_parser.rules = preprocess_splits(disasm_parser.rules, asm_emitted)
            logging.debug(disasm_parser.rules)

            disasm_gen = ExpandGenerator(disasm_parser.variables, disasm_parser.rules)
            disasm_emitted = disasm_gen.generate()
            all_disasm_emitted.extend(disasm_emitted)
            logging.debug(disasm_emitted)

        return all_disasm_emitted, all_asm_emitted


@dataclass
class ExpandGenerator(Generator):
    variables: Dict = field(default_factory=dict)
    rules: List = field(default_factory=list)
    rule_i: int = field(default=0)
    emitted: List = field(default_factory=list)

    def advance(self):
        if self.rule_i >= len(self.rules):
            return None

        next_rule = self.rules[self.rule_i]
        self.rule_i += 1
        return next_rule

    def peek(self, k=0):
        if (self.rule_i + k) >= len(self.rules):
            return None

        return self.rules[self.rule_i + k]

    def seek(self, i=0):
        if i >= len(self.rules):
            raise RuntimeError(f'Cannot seek to "{i}" >= "{len(self.rules)}".')
        self.rule_i = i

    def generate_expr(self, expr, out, level):
        if isinstance(expr.lhs, RuleVarRef):
            child = expr.lhs
            counter = self.variables[child.name].counter
            counter.reset()
            next_k = counter.next()
            while not isinstance(next_k, type(None)):
                prev_rule_i = self.rule_i
                self.generate_expr(
                    RuleExpr(
                        RuleHex(
                            next_k,
                            is_offset=(not counter.is_reg),
                            is_signed=counter.is_signed,
                            var_names=[self.variables[child.name].name],
                            split_i=child.split_i,
                            seq_i=child.seq_i,
                        ),
                        expr.op,
                        expr.rhs,
                    ),
                    out[:],
                    level + 1,
                )
                next_k = counter.next()
                self.seek(prev_rule_i)

            # Next tokens were already parsed on children, force flush
            while not isinstance(child, type(None)):
                child = self.advance()
        elif isinstance(expr.lhs, RuleHex):
            if isinstance(expr.rhs, RuleVarRef):
                child = expr.rhs
                counter = self.variables[child.name].counter
                counter.reset()
                next_k = counter.next()
                while not isinstance(next_k, type(None)):
                    prev_rule_i = self.rule_i
                    self.generate_expr(
                        RuleExpr(
                            expr.lhs,
                            expr.op,
                            RuleHex(
                                next_k,
                                is_offset=(not counter.is_reg),
                                is_signed=counter.is_signed,
                                var_names=[self.variables[child.name].name],
                                split_i=child.split_i,
                                seq_i=child.seq_i,
                            ),
                        ),
                        out[:],
                        level + 1,
                    )
                    next_k = counter.next()
                    self.seek(prev_rule_i)

                # Next tokens were already parsed on children, force flush
                while not isinstance(child, type(None)):
                    child = self.advance()
            elif isinstance(expr.rhs, RuleHex):
                var_names = []
                var_names_set = set()
                if isinstance(expr.lhs, RuleVarRef):
                    name = self.variables[expr.lhs.name].name
                    var_names.append(name)
                    var_names_set.add(name)
                elif isinstance(expr.lhs, RuleHex):
                    for name in expr.lhs.var_names:
                        var_names.append(name)
                        var_names_set.add(name)
                if isinstance(expr.rhs, RuleVarRef):
                    name = self.variables[expr.rhs.name].name
                    if name not in var_names_set:
                        var_names.append(name)
                        var_names_set.add(name)
                elif isinstance(expr.rhs, RuleHex):
                    for name in expr.rhs.var_names:
                        if name not in var_names_set:
                            var_names.append(name)
                            var_names_set.add(name)
                out.append(
                    RuleHex(
                        expr.eval(self.variables),
                        is_offset=(expr.lhs.is_offset or expr.rhs.is_offset),
                        is_signed=(expr.lhs.is_signed or expr.rhs.is_signed),
                        var_names=var_names,
                        split_i=min(expr.lhs.split_i, expr.rhs.split_i),  # ???
                        seq_i=min(expr.lhs.seq_i, expr.rhs.seq_i),  # ???
                    )
                )
                self.emitted.append(out)
            elif isinstance(expr.rhs, RuleExpr):
                child = expr.rhs
                prev_rule_i = self.rule_i
                self.generate_expr(child, out[:], level + 1)
                self.seek(prev_rule_i)
                child_emitted = self.emitted[:]
                self.emitted = []
                for rules in child_emitted:
                    # WARN: Assuming sub-expression only generates a single RuleHex
                    rule = rules[-1]
                    prev_rule_i = self.rule_i
                    self.generate_expr(
                        RuleExpr(
                            expr.lhs,
                            expr.op,
                            rule,
                        ),
                        out[:],
                        level + 1,
                    )
                    self.seek(prev_rule_i)

                # Next tokens were already parsed on children, force flush
                while not isinstance(child, type(None)):
                    child = self.advance()
            else:
                raise RuntimeError(f'Cannot generate rhs "{expr.rhs}".')
        elif isinstance(expr.lhs, RuleExpr):
            child = expr.lhs
            prev_rule_i = self.rule_i
            self.generate_expr(child, out[:], level + 1)
            self.seek(prev_rule_i)
            child_emitted = self.emitted[:]
            self.emitted = []
            for rules in child_emitted:
                # WARN: Assuming sub-expression only generates a single RuleHex
                rule = rules[-1]
                prev_rule_i = self.rule_i
                self.generate_expr(
                    RuleExpr(
                        rule,
                        expr.op,
                        expr.rhs,
                    ),
                    out[:],
                    level + 1,
                )
                self.seek(prev_rule_i)

            # Next tokens were already parsed on children, force flush
            while not isinstance(child, type(None)):
                child = self.advance()
        else:
            raise RuntimeError(f'Cannot generate lhs "{expr.lhs}".')

    def generate_child(self, child, out, level):
        while self.peek():
            if not child:
                child = self.advance()
            if isinstance(child, RuleVarRef):
                counter = self.variables[child.name].counter
                counter.reset()
                next_k = counter.next()
                while not isinstance(next_k, type(None)):
                    prev_rule_i = self.rule_i
                    self.generate_child(
                        (
                            RuleLiteral(
                                next_k,
                                var_names=[self.variables[child.name].name],
                                split_i=child.split_i,
                                seq_i=child.seq_i,
                            )
                            if counter.is_name_output
                            else RuleHex(
                                next_k,
                                is_offset=(not counter.is_reg),
                                is_signed=counter.is_signed,
                                var_names=[self.variables[child.name].name],
                                split_i=child.split_i,
                                seq_i=child.seq_i,
                            )
                        ),
                        out[:],
                        level + 1,
                    )
                    next_k = counter.next()
                    self.seek(prev_rule_i)

                # Next tokens were already parsed on children, force flush
                while not isinstance(child, type(None)):
                    child = self.advance()
            elif isinstance(child, RuleExpr):
                prev_emitted = self.emitted[:]
                self.emitted = []
                prev_rule_i = self.rule_i
                self.generate_expr(child, out[:], level + 1)
                self.seek(prev_rule_i)
                child_emitted = self.emitted[:]
                self.emitted = []
                for rules in child_emitted:
                    # WARN: Assuming sub-expression only generates a single RuleHex
                    rule = rules[-1]
                    self.generate_child(None, out[:] + [rule], level + 1)

                    self.generate_child(None, out[:], level + 1)
                    self.seek(prev_rule_i)
                self.emitted.extend(prev_emitted)

                # Next tokens were already parsed on children, force flush
                while not isinstance(child, type(None)):
                    child = self.advance()
            elif isinstance(child, (RuleLiteral, RuleHex)):
                out.append(child)
            elif isinstance(child, RuleEnd):
                break
            else:
                raise RuntimeError(f'Cannot generate rule "{child}".')
            child = None
        if isinstance(child, RuleEnd):
            self.emitted.append(out)

    def generate(self):
        logging.debug(self.rules)
        self.generate_child(None, [], 0)
        return self.emitted


def text_to_bmp(text, name):
    print(f'Generating {name}.bmp: width="{85 * len(text)}", text="{text}"')
    filename = f"{name}.bmp"
    cmd = [
        "convert",
        "-size",
        f"{85 * len(text)}x72",
        "xc:white",
        "-font",
        "resources/NotoSansMono-Regular.ttf",
        "-pointsize",
        "72",
        "-fill",
        "black",
        "-draw",
        f"text 25, 65 '{text}'",
        filename,
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True)
        output_file = Path(f"./{filename}")
        if not output_file.exists():
            print(
                f"convert returned success for {filename}, but file not found:\n{proc.stdout}\n{proc.stderr}",
                file=sys.stderr,
            )
    except subprocess.CalledProcessError as e:
        print(
            f"convert for {filename} failed with code {e.returncode}):\n{e.stdout}\n{e.stderr}",
            file=sys.stderr,
        )
        try:
            os.remove(filename)
        except OSError:
            pass
        raise e


def text_to_svg(name):
    Path("./out_svg").mkdir(parents=True, exist_ok=True)
    output_file = Path(f"./out_svg/{name}.svg")
    filename = f"{name}.bmp"
    cmd = [
        "potrace",
        "-s",
        filename,
        "-o",
        output_file.absolute(),
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True)
        output_file = Path(f"./{filename}")
        if not output_file.exists():
            print(
                f"potrace returned success for {filename}, but file not found:\n{proc.stdout}\n{proc.stderr}",
                file=sys.stderr,
            )
    except subprocess.CalledProcessError as e:
        print(
            f"potrace for {filename} failed with code {e.returncode}):\n{e.stdout}\n{e.stderr}",
            file=sys.stderr,
        )
        raise e
    finally:
        try:
            os.remove(filename)
        except OSError:
            pass


def ttf_to_ttx():
    cmd = ["./ttf_to_ttx.sh"]
    try:
        proc = subprocess.run(cmd, capture_output=True, shell=True)
    except subprocess.CalledProcessError as e:
        print(
            f"ttf_to_ttx failed with code {e.returncode}):\n{e.stdout}\n{e.stderr}", file=sys.stderr,
        )
        raise e


def ttx_to_ttf():
    cmd = ["./ttx_to_ttf.sh"]
    try:
        proc = subprocess.run(cmd, capture_output=True, shell=True)
    except subprocess.CalledProcessError as e:
        print(
            f"ttx_to_ttf failed with code {e.returncode}):\n{e.stdout}\n{e.stderr}",
            file=sys.stderr,
        )
        raise e


def digit_to_name(x):
    options = {
        0: "zero",
        1: "one",
        2: "two",
        3: "three",
        4: "four",
        5: "five",
        6: "six",
        7: "seven",
        8: "eight",
        9: "nine",
        10: "a",
        11: "b",
        12: "c",
        13: "d",
        14: "e",
        15: "f",
    }
    if isinstance(x, str):
        x = int(x, 16)
    return options[x]


def emit_multiple_subst(emitter, index):
    tmpl = """
    <Lookup index="__i__">
      <LookupType value="2"/>
      <LookupFlag value="0"/>
      <MultipleSubst index="0">
      </MultipleSubst>
    </Lookup>
"""
    tmpl = tmpl.replace("__i__", str(index))
    soup = BeautifulSoup(tmpl, features="xml")

    lookup = soup.find("Lookup")
    lookup_tag_multiple_subst = lookup.find("MultipleSubst")
    for key in emitter.in_glyphs.keys():
        tag_substitution = soup.new_tag(
            "Substitution",
            attrs={
                "in": key,
                "out": emitter.in_glyphs[key],
            },
        )
        lookup_tag_multiple_subst.append(tag_substitution)

    return soup


def emit_ligature_subst(emitter, index):
    tmpl = """
    <Lookup index="__i__">
      <LookupType value="4"/>
      <LookupFlag value="0"/>
      <LigatureSubst index="0">
      </LigatureSubst>
    </Lookup>
"""
    tmpl = tmpl.replace("__i__", str(index))
    soup = BeautifulSoup(tmpl, features="xml")

    lookup = soup.find("Lookup")
    lookup_tag_ligature_subst = lookup.find("LigatureSubst")
    for key in emitter.ligature_set_glyphs.keys():
        tag_ligature_set = soup.new_tag(
            "LigatureSet",
            attrs={
                "glyph": key,
            },
        )
        emitLookup_ligature_set = emitter.ligature_set_glyphs[key]
        for ligature_key in emitLookup_ligature_set.keys():
            tag_ligature = soup.new_tag(
                "Ligature",
                attrs={
                    "components": ligature_key,
                    "glyph": emitLookup_ligature_set[ligature_key],
                },
            )
            tag_ligature_set.append(tag_ligature)
        lookup_tag_ligature_subst.append(tag_ligature_set)

    return soup


def emit_chain_suffixes(
    prefixes, suffix_key, lookup6_tmpl, lookup7_tmpl, offset_suffix_str
):
    lookup6 = BeautifulSoup(
        lookup6_tmpl.replace("__i__", str(lookup_list_i)).replace(
            "__i2__", str(lookup_list_i + 1)
        ),
        features="xml",
    )
    lookup6_tag_extension_subst0 = lookup6.find("BacktrackClassDef")
    lookup7 = BeautifulSoup(
        lookup7_tmpl.replace("__i__", str(lookup_list_i + 1)),
        features="xml",
    )
    lookup7_tag_multiple_subst = lookup7.find("MultipleSubst")

    emitLookup7 = EmitLookupMultipleSubst()
    for i in range(0x10):
        emitLookup7.in_glyphs[f"offset_{i:01x}_{offset_suffix_str}"] = (
            f"offset_{i:01x}_{offset_suffix_str},{suffix_key}"
        )
    for key in emitLookup7.in_glyphs.keys():
        tag_substitution = soup.new_tag(
            "Substitution",
            attrs={
                "in": key,
                "out": emitLookup7.in_glyphs[key],
            },
        )
        lookup7_tag_multiple_subst.append(tag_substitution)

    for prefix in prefixes:
        tag_class_def = soup.new_tag(
            "ClassDef",
            attrs={
                "glyph": prefix,
                "class": "1",
            },
        )
        lookup6_tag_extension_subst0.append(tag_class_def)

    return lookup6, lookup7


def preprocess_literals(splits):
    splits = sorted(splits, key=lambda x: x.seq_i)

    merged_disasm_instruction = []
    disasm_str = ""
    prev_split_i = splits[0].split_i
    prev_seq_i = splits[0].seq_i
    for r in splits:
        # TODO/FIXME
        # if prev_split_i == r.split_i and isinstance(r, RuleLiteral):
        if isinstance(r, RuleLiteral):
            disasm_str += r.eval()
        else:
            if disasm_str:
                is_signed = False
                if isinstance(r, RuleHex) and r.is_signed:
                    if disasm_str[-1] == "+":
                        disasm_str = disasm_str[:-1]
                    is_signed = True
                merged_disasm_instruction.append(
                    RuleLiteral(disasm_str, is_signed=is_signed, split_i=prev_split_i, seq_i=prev_seq_i)
                )
                disasm_str = ""
            if isinstance(r, RuleLiteral):
                disasm_str = r.eval()
            else:
                merged_disasm_instruction.append(r)
        prev_split_i = r.split_i
        prev_seq_i = r.seq_i

    if disasm_str:
        merged_disasm_instruction.append(RuleLiteral(disasm_str, split_i=prev_split_i, seq_i=prev_seq_i))
        disasm_str = ""

    return merged_disasm_instruction


def preprocess_splits(disasm_rules, asm_emitted):
    asm_mappings = {}
    for asm_rules in asm_emitted:
        split_i = 0
        for i, rule in enumerate(asm_rules):
            if len(rule.var_names) > 0:
                split_i += 1
            for name in rule.var_names:
                asm_mappings[name] = split_i
            rule.split_i = split_i
            rule.seq_i = i

    split_i = 0
    disasm_splits = []
    for i, rule in enumerate(disasm_rules):
        if not isinstance(rule, RuleEnd):
            if isinstance(rule, RuleVarRef):
                name = rule.name
                mapping_i = asm_mappings[name]
                split_i = mapping_i
            elif len(rule.var_names) > 0:
                for name in rule.var_names:
                    assert len(rule.var_names) == 1
                    mapping_i = asm_mappings[name]
                    split_i = mapping_i
            rule.split_i = split_i
            rule.seq_i = i
        disasm_splits.append(rule)

    # TODO/FIXME
    return sorted(disasm_splits, key=lambda x: x.split_i)
    # return disasm_splits


def emit_chain_init_fini(
    seen_lookup_ambiguous,
    seen_lookup_init_fini_mappings,
    tmpl_chain_context_subst_init_fini_lit,
    tmpl_ligature_subst_init_lit,
    lookup_list_i,
):
    # Note: Assuming ambiguous cases to only have an offset in the middle (no u16 or other variants)
    lookups = []
    for key in seen_lookup_ambiguous:
        if len(list(seen_lookup_ambiguous[key].keys())) > 1:
            raise RuntimeError(f"len>1 {seen_lookup_ambiguous[key]}")

        # Next chars in init prefix
        assert len(list(seen_lookup_ambiguous[key].keys())) == 1
        component_key = list(seen_lookup_ambiguous[key].keys())[0]
        for prefix in seen_lookup_ambiguous[key][component_key]:
            lookup0 = BeautifulSoup(
                tmpl_chain_context_subst_init_fini_lit.replace("__i__", str(lookup_list_i)),
                features="xml",
            )
            tag_ext = lookup0.find("ExtensionSubst", {"index": "0"})
            tag_chain_ctx = tag_ext.find("ChainContextSubst")

            # First char in init prefix
            tag_cov = soup.new_tag(
                "InputCoverage",
                attrs={
                    "index": 0,
                },
            )
            tag_glyph = soup.new_tag(
                "Glyph",
                attrs={
                    "value": key,
                },
            )
            tag_cov.append(tag_glyph)
            tag_chain_ctx.append(tag_cov)

            la_i = 0
            for component in component_key.split(","):
                tag_cov = soup.new_tag(
                    "LookAheadCoverage",
                    attrs={
                        "index": la_i,
                    },
                )
                la_i += 1
                tag_glyph = soup.new_tag(
                    "Glyph",
                    attrs={
                        "value": component,
                    },
                )
                tag_cov.append(tag_glyph)
                tag_chain_ctx.append(tag_cov)

            # Chars for offset
            for i in range(2):
                tag_cov = soup.new_tag(
                    "LookAheadCoverage",
                    attrs={
                        "index": la_i,
                    },
                )
                la_i += 1
                for offset_i in range(16):
                    tag_glyph = soup.new_tag(
                        "Glyph",
                        attrs={
                            "value": digit_to_name(offset_i),
                        },
                    )
                    tag_cov.append(tag_glyph)
                tag_chain_ctx.append(tag_cov)

            # Chars for fini suffix
            fini = seen_lookup_init_fini_mappings[prefix].split(",")[1]
            for nibble in fini:
                tag_cov = soup.new_tag(
                    "LookAheadCoverage",
                    attrs={
                        "index": la_i,
                    },
                )
                la_i += 1
                tag_glyph = soup.new_tag(
                    "Glyph",
                    attrs={
                        "value": digit_to_name(nibble),
                    },
                )
                tag_cov.append(tag_glyph)
                tag_chain_ctx.append(tag_cov)
            tag_cov = soup.new_tag(
                "LookAheadCoverage",
                attrs={
                    "index": la_i,
                },
            )
            la_i += 1
            tag_glyph = soup.new_tag(
                "Glyph",
                attrs={
                    "value": ".null",
                },
            )
            tag_cov.append(tag_glyph)
            tag_chain_ctx.append(tag_cov)

            # Sub rule for next lookup
            tag_ext = lookup0.find("ExtensionSubst", {"index": "1"})
            tag_chain_ctx = tag_ext.find("ChainContextSubst")
            tag_cov = soup.new_tag("Coverage")
            tag_glyph = soup.new_tag(
                "Glyph",
                attrs={
                    "value": key,
                },
            )
            tag_cov.append(tag_glyph)
            tag_chain_ctx.append(tag_cov)
            tag_chain_subruleset = soup.new_tag("ChainSubRuleSet", attrs={ "index":"0" })

            subrule_i = 0
            for offset_i in range(16):
                for offset_j in range(16):
                    tmpl_chain = """
                                    <ChainSubRule index="__subrule_i__">
                                      <SubstLookupRecord index="0">
                                        <SequenceIndex value="0"/>
                                        <LookupListIndex value="__i2__"/>
                                      </SubstLookupRecord>
                                    </ChainSubRule>"""
                    tag_chain_subrule = BeautifulSoup(
                        tmpl_chain.replace("__subrule_i__", str(subrule_i)).replace("__i2__", str(lookup_list_i + 1)),
                        features="xml",
                    )
                    subrule_i += 1
                    tag_subrule = tag_chain_subrule.find("ChainSubRule")

                    la_i = 0
                    for component in component_key.split(","):
                        tag_glyph = soup.new_tag(
                            "LookAhead",
                            attrs={
                                "index": la_i,
                                "value": component,
                            },
                        )
                        la_i += 1
                        tag_subrule.append(tag_glyph)
                    tag_glyph = soup.new_tag(
                        "LookAhead",
                        attrs={
                            "index": la_i,
                            "value": digit_to_name(offset_i),
                        },
                    )
                    la_i += 1
                    tag_subrule.append(tag_glyph)
                    tag_glyph = soup.new_tag(
                        "LookAhead",
                        attrs={
                            "index": la_i,
                            "value": digit_to_name(offset_j),
                        },
                    )
                    la_i += 1
                    tag_subrule.append(tag_glyph)
                    for nibble in fini:
                        tag_glyph = soup.new_tag(
                            "LookAhead",
                            attrs={
                                "index": la_i,
                                "value": digit_to_name(nibble),
                            },
                        )
                        la_i += 1
                        tag_subrule.append(tag_glyph)

                    tag_chain_subruleset.append(tag_chain_subrule)
            tag_chain_ctx.append(tag_chain_subruleset)

            lookups.append([lookup0, True])
            lookup_list_i += 1

            # Generate ligature for next lookup
            lookup1 = BeautifulSoup(
                tmpl_ligature_subst_init_lit.replace("__i__", str(lookup_list_i)),
                features="xml",
            )
            lookup1_tag_ligature_subst = lookup1.find("LigatureSubst")
            tag_ligature_set = soup.new_tag(
                "LigatureSet",
                attrs={
                    "glyph": key,
                },
            )
            tag_ligature = soup.new_tag(
                "Ligature",
                attrs={
                    "components": component_key,
                    "glyph": prefix
                },
            )
            tag_ligature_set.append(tag_ligature)
            lookup1_tag_ligature_subst.append(tag_ligature_set)

            lookups.append([lookup1, False])
            lookup_list_i += 1

    return lookups, lookup_list_i


with open(sys.argv[1], "rb") as f:
    g = Generator()
    print("Computing rules.")
    disasm_emitted, asm_emitted = g.generate(json.load(f))
    print("Emitted lengths:", len(disasm_emitted), len(asm_emitted))
    assert len(disasm_emitted) == len(asm_emitted)

    glyph_chains = []
    glyph_ids = {}
    glyph_i = 0
    is_offset_seen = False
    seen_init_fini = set()
    seen_signed_literals = set()
    seen_fini_with_asms = set()
    for i in range(len(disasm_emitted)):
        disasm_instruction = disasm_emitted[i]
        asm_instruction = asm_emitted[i]

        disasm_instruction = preprocess_literals(disasm_instruction)
        logging.debug((asm_instruction, disasm_instruction))

        asm_i = 0
        prev_asm_i = 0
        prev_split_i = 0
        prev_is_offset = False
        disasm_str = ""
        glyph_chain = []
        lookup_i = 0
        is_signed = False
        asms_mappings = {}
        for ri in range(len(disasm_instruction)):
            r = disasm_instruction[ri]
            if isinstance(r, RuleLiteral):
                if prev_is_offset != r.is_offset:
                    lookup_i += 1
                    prev_is_offset = r.is_offset

                is_signed = r.is_signed
                disasm_str = r.eval()

                asms = []
                while (
                    asm_i < len(asm_instruction)
                    and asm_instruction[asm_i].is_offset == False
                    # TODO/FIXME
                    # and asm_instruction[asm_i].split_i == r.split_i
                ):
                    asms.append(asm_instruction[asm_i].glyph_str())
                    asm_i += 1
                asms_mappings[ri] = asms

                is_distinct_glyph = disasm_str not in glyph_ids
                if (
                    disasm_str
                    and (ri == 0 or ri == len(disasm_instruction) - 1)
                    and len(disasm_instruction) > 2
                    and isinstance(disasm_instruction[-1], RuleLiteral)
                ):
                    # ["ADC A,(IX+o)", "DD 8E o"],
                    # ["SRA (IX+o)", "DD CB o 2E"],
                    if ri == 0:
                        init_fini = f'{disasm_str}({"".join(asms)})_{disasm_instruction[-1].eval()}'
                    else:
                        init_fini = f'{disasm_str}({"".join(asms_mappings[0])})_{disasm_instruction[-1].eval()}({"".join(asms)})'
                    if init_fini not in seen_init_fini:
                        is_distinct_glyph = True
                        seen_init_fini.add(init_fini)
                if is_distinct_glyph:
                    glyph_name = (
                        f"{glyph_i:08X}_{re.sub('[^A-Za-z0-9]+', '_', disasm_str)}"
                    )
                    glyph_i += 1
                    glyph_ids[disasm_str] = EmitGlyph(glyph_name, asms, lookup_i)
                    text_to_bmp(disasm_str, glyph_name)
                    text_to_svg(glyph_name)
                if is_signed:
                    seen_signed_literals.add(glyph_ids[disasm_str].name)
                prev_asm_i = asm_i
                glyph_chain.append(glyph_ids[disasm_str])
                if lookup_i == 2 and len(asms) > 0:
                   seen_fini_with_asms.add(glyph_ids[disasm_str].name)
            else:
                if prev_is_offset != r.is_offset:
                    lookup_i += 1
                    prev_is_offset = r.is_offset

                offset_str = r.eval()
                logging.debug((offset_str, prev_asm_i, asm_i))

                asm_i = prev_asm_i
                asms = []
                while (
                    asm_i < len(asm_instruction)
                    and asm_instruction[asm_i].is_offset == True
                    # TODO/FIXME
                    # and asm_instruction[asm_i].split_i == r.split_i
                ):
                    asms.append(asm_instruction[asm_i].glyph_str())
                    asm_i += 1
                asms_mappings[ri] = asms

                for nibble in f"{offset_str:02x}":
                    if nibble not in glyph_ids:
                        glyph_name = f"offset_{nibble}"
                        glyph_ids[nibble] = EmitGlyph(
                            glyph_name, asms, lookup_i, is_offset=True
                        )
                        text_to_bmp(f"{nibble}", glyph_name)
                        text_to_bmp(f"{nibble}", f"{glyph_name}_2")
                        text_to_bmp(f"{nibble}", f"{glyph_name}_3")
                        text_to_bmp(f"{nibble}", f"{glyph_name}_4")
                        text_to_bmp(f"{nibble}", f"{glyph_name}_s")
                        text_to_bmp(f"{nibble}", f"{glyph_name}_s2")
                        text_to_svg(glyph_name)
                        text_to_svg(f"{glyph_name}_2")
                        text_to_svg(f"{glyph_name}_3")
                        text_to_svg(f"{glyph_name}_4")
                        text_to_svg(f"{glyph_name}_s")
                        text_to_svg(f"{glyph_name}_s2")
                    glyph_chain.append(glyph_ids[nibble])

        glyph_chains.append(glyph_chain)

    ttf_to_ttx()

    gpos_tmpl = """
<GPOS>
    <Version value="0x00010000"/>
    <ScriptList>
      <ScriptRecord index="0">
        <ScriptTag value="latn"/>
        <Script>
          <DefaultLangSys>
            <ReqFeatureIndex value="65535"/>
            <FeatureIndex index="0" value="0"/>
          </DefaultLangSys>
        </Script>
      </ScriptRecord>
    </ScriptList>
    <FeatureList>
      <FeatureRecord index="0">
        <FeatureTag value="kern"/>
        <Feature>
          <LookupListIndex index="0" value="0"/>
        </Feature>
      </FeatureRecord>
    </FeatureList>
    <LookupList>
      <Lookup index="0">
        <LookupType value="8"/>
        <LookupFlag value="0"/>
        <ChainContextPos index="0" Format="3">
          <BacktrackCoverage index="0">
            <Glyph value="offset_0_3"/>
            <Glyph value="offset_1_3"/>
            <Glyph value="offset_2_3"/>
            <Glyph value="offset_3_3"/>
            <Glyph value="offset_4_3"/>
            <Glyph value="offset_5_3"/>
            <Glyph value="offset_6_3"/>
            <Glyph value="offset_7_3"/>
            <Glyph value="offset_8_3"/>
            <Glyph value="offset_9_3"/>
            <Glyph value="offset_a_3"/>
            <Glyph value="offset_b_3"/>
            <Glyph value="offset_c_3"/>
            <Glyph value="offset_d_3"/>
            <Glyph value="offset_e_3"/>
            <Glyph value="offset_f_3"/>
          </BacktrackCoverage>
          <BacktrackCoverage index="1">
            <Glyph value="offset_0_2"/>
            <Glyph value="offset_1_2"/>
            <Glyph value="offset_2_2"/>
            <Glyph value="offset_3_2"/>
            <Glyph value="offset_4_2"/>
            <Glyph value="offset_5_2"/>
            <Glyph value="offset_6_2"/>
            <Glyph value="offset_7_2"/>
            <Glyph value="offset_8_2"/>
            <Glyph value="offset_9_2"/>
            <Glyph value="offset_a_2"/>
            <Glyph value="offset_b_2"/>
            <Glyph value="offset_c_2"/>
            <Glyph value="offset_d_2"/>
            <Glyph value="offset_e_2"/>
            <Glyph value="offset_f_2"/>
          </BacktrackCoverage>
          <BacktrackCoverage index="2">
            <Glyph value="offset_0"/>
            <Glyph value="offset_1"/>
            <Glyph value="offset_2"/>
            <Glyph value="offset_3"/>
            <Glyph value="offset_4"/>
            <Glyph value="offset_5"/>
            <Glyph value="offset_6"/>
            <Glyph value="offset_7"/>
            <Glyph value="offset_8"/>
            <Glyph value="offset_9"/>
            <Glyph value="offset_a"/>
            <Glyph value="offset_b"/>
            <Glyph value="offset_c"/>
            <Glyph value="offset_d"/>
            <Glyph value="offset_e"/>
            <Glyph value="offset_f"/>
          </BacktrackCoverage>
          <InputCoverage index="0">
            <Glyph value="offset_0_4"/>
            <Glyph value="offset_1_4"/>
            <Glyph value="offset_2_4"/>
            <Glyph value="offset_3_4"/>
            <Glyph value="offset_4_4"/>
            <Glyph value="offset_5_4"/>
            <Glyph value="offset_6_4"/>
            <Glyph value="offset_7_4"/>
            <Glyph value="offset_8_4"/>
            <Glyph value="offset_9_4"/>
            <Glyph value="offset_a_4"/>
            <Glyph value="offset_b_4"/>
            <Glyph value="offset_c_4"/>
            <Glyph value="offset_d_4"/>
            <Glyph value="offset_e_4"/>
            <Glyph value="offset_f_4"/>
          </InputCoverage>
          <PosLookupRecord index="0">
            <SequenceIndex value="0"/>
            <LookupListIndex value="1"/>
          </PosLookupRecord>
        </ChainContextPos>
        <ChainContextPos index="1" Format="3">
          <BacktrackCoverage index="0">
            <Glyph value="offset_0_2"/>
            <Glyph value="offset_1_2"/>
            <Glyph value="offset_2_2"/>
            <Glyph value="offset_3_2"/>
            <Glyph value="offset_4_2"/>
            <Glyph value="offset_5_2"/>
            <Glyph value="offset_6_2"/>
            <Glyph value="offset_7_2"/>
            <Glyph value="offset_8_2"/>
            <Glyph value="offset_9_2"/>
            <Glyph value="offset_a_2"/>
            <Glyph value="offset_b_2"/>
            <Glyph value="offset_c_2"/>
            <Glyph value="offset_d_2"/>
            <Glyph value="offset_e_2"/>
            <Glyph value="offset_f_2"/>
          </BacktrackCoverage>
          <BacktrackCoverage index="1">
            <Glyph value="offset_0"/>
            <Glyph value="offset_1"/>
            <Glyph value="offset_2"/>
            <Glyph value="offset_3"/>
            <Glyph value="offset_4"/>
            <Glyph value="offset_5"/>
            <Glyph value="offset_6"/>
            <Glyph value="offset_7"/>
            <Glyph value="offset_8"/>
            <Glyph value="offset_9"/>
            <Glyph value="offset_a"/>
            <Glyph value="offset_b"/>
            <Glyph value="offset_c"/>
            <Glyph value="offset_d"/>
            <Glyph value="offset_e"/>
            <Glyph value="offset_f"/>
          </BacktrackCoverage>
          <InputCoverage index="0">
            <Glyph value="offset_0_3"/>
            <Glyph value="offset_1_3"/>
            <Glyph value="offset_2_3"/>
            <Glyph value="offset_3_3"/>
            <Glyph value="offset_4_3"/>
            <Glyph value="offset_5_3"/>
            <Glyph value="offset_6_3"/>
            <Glyph value="offset_7_3"/>
            <Glyph value="offset_8_3"/>
            <Glyph value="offset_9_3"/>
            <Glyph value="offset_a_3"/>
            <Glyph value="offset_b_3"/>
            <Glyph value="offset_c_3"/>
            <Glyph value="offset_d_3"/>
            <Glyph value="offset_e_3"/>
            <Glyph value="offset_f_3"/>
          </InputCoverage>
          <LookAheadCoverage index="0">
            <Glyph value="offset_0_4"/>
            <Glyph value="offset_1_4"/>
            <Glyph value="offset_2_4"/>
            <Glyph value="offset_3_4"/>
            <Glyph value="offset_4_4"/>
            <Glyph value="offset_5_4"/>
            <Glyph value="offset_6_4"/>
            <Glyph value="offset_7_4"/>
            <Glyph value="offset_8_4"/>
            <Glyph value="offset_9_4"/>
            <Glyph value="offset_a_4"/>
            <Glyph value="offset_b_4"/>
            <Glyph value="offset_c_4"/>
            <Glyph value="offset_d_4"/>
            <Glyph value="offset_e_4"/>
            <Glyph value="offset_f_4"/>
          </LookAheadCoverage>
          <PosLookupRecord index="0">
            <SequenceIndex value="0"/>
            <LookupListIndex value="1"/>
          </PosLookupRecord>
        </ChainContextPos>
        <ChainContextPos index="2" Format="3">
          <BacktrackCoverage index="0">
            <Glyph value="offset_0"/>
            <Glyph value="offset_1"/>
            <Glyph value="offset_2"/>
            <Glyph value="offset_3"/>
            <Glyph value="offset_4"/>
            <Glyph value="offset_5"/>
            <Glyph value="offset_6"/>
            <Glyph value="offset_7"/>
            <Glyph value="offset_8"/>
            <Glyph value="offset_9"/>
            <Glyph value="offset_a"/>
            <Glyph value="offset_b"/>
            <Glyph value="offset_c"/>
            <Glyph value="offset_d"/>
            <Glyph value="offset_e"/>
            <Glyph value="offset_f"/>
          </BacktrackCoverage>
          <InputCoverage index="0">
            <Glyph value="offset_0_2"/>
            <Glyph value="offset_1_2"/>
            <Glyph value="offset_2_2"/>
            <Glyph value="offset_3_2"/>
            <Glyph value="offset_4_2"/>
            <Glyph value="offset_5_2"/>
            <Glyph value="offset_6_2"/>
            <Glyph value="offset_7_2"/>
            <Glyph value="offset_8_2"/>
            <Glyph value="offset_9_2"/>
            <Glyph value="offset_a_2"/>
            <Glyph value="offset_b_2"/>
            <Glyph value="offset_c_2"/>
            <Glyph value="offset_d_2"/>
            <Glyph value="offset_e_2"/>
            <Glyph value="offset_f_2"/>
          </InputCoverage>
          <LookAheadCoverage index="0">
            <Glyph value="offset_0_3"/>
            <Glyph value="offset_1_3"/>
            <Glyph value="offset_2_3"/>
            <Glyph value="offset_3_3"/>
            <Glyph value="offset_4_3"/>
            <Glyph value="offset_5_3"/>
            <Glyph value="offset_6_3"/>
            <Glyph value="offset_7_3"/>
            <Glyph value="offset_8_3"/>
            <Glyph value="offset_9_3"/>
            <Glyph value="offset_a_3"/>
            <Glyph value="offset_b_3"/>
            <Glyph value="offset_c_3"/>
            <Glyph value="offset_d_3"/>
            <Glyph value="offset_e_3"/>
            <Glyph value="offset_f_3"/>
          </LookAheadCoverage>
          <LookAheadCoverage index="1">
            <Glyph value="offset_0_4"/>
            <Glyph value="offset_1_4"/>
            <Glyph value="offset_2_4"/>
            <Glyph value="offset_3_4"/>
            <Glyph value="offset_4_4"/>
            <Glyph value="offset_5_4"/>
            <Glyph value="offset_6_4"/>
            <Glyph value="offset_7_4"/>
            <Glyph value="offset_8_4"/>
            <Glyph value="offset_9_4"/>
            <Glyph value="offset_a_4"/>
            <Glyph value="offset_b_4"/>
            <Glyph value="offset_c_4"/>
            <Glyph value="offset_d_4"/>
            <Glyph value="offset_e_4"/>
            <Glyph value="offset_f_4"/>
          </LookAheadCoverage>
          <PosLookupRecord index="0">
            <SequenceIndex value="0"/>
            <LookupListIndex value="1"/>
          </PosLookupRecord>
        </ChainContextPos>
        <ChainContextPos index="3" Format="3">
          <InputCoverage index="0">
            <Glyph value="offset_0"/>
            <Glyph value="offset_1"/>
            <Glyph value="offset_2"/>
            <Glyph value="offset_3"/>
            <Glyph value="offset_4"/>
            <Glyph value="offset_5"/>
            <Glyph value="offset_6"/>
            <Glyph value="offset_7"/>
            <Glyph value="offset_8"/>
            <Glyph value="offset_9"/>
            <Glyph value="offset_a"/>
            <Glyph value="offset_b"/>
            <Glyph value="offset_c"/>
            <Glyph value="offset_d"/>
            <Glyph value="offset_e"/>
            <Glyph value="offset_f"/>
          </InputCoverage>
          <LookAheadCoverage index="0">
            <Glyph value="offset_0_2"/>
            <Glyph value="offset_1_2"/>
            <Glyph value="offset_2_2"/>
            <Glyph value="offset_3_2"/>
            <Glyph value="offset_4_2"/>
            <Glyph value="offset_5_2"/>
            <Glyph value="offset_6_2"/>
            <Glyph value="offset_7_2"/>
            <Glyph value="offset_8_2"/>
            <Glyph value="offset_9_2"/>
            <Glyph value="offset_a_2"/>
            <Glyph value="offset_b_2"/>
            <Glyph value="offset_c_2"/>
            <Glyph value="offset_d_2"/>
            <Glyph value="offset_e_2"/>
            <Glyph value="offset_f_2"/>
          </LookAheadCoverage>
          <LookAheadCoverage index="1">
            <Glyph value="offset_0_3"/>
            <Glyph value="offset_1_3"/>
            <Glyph value="offset_2_3"/>
            <Glyph value="offset_3_3"/>
            <Glyph value="offset_4_3"/>
            <Glyph value="offset_5_3"/>
            <Glyph value="offset_6_3"/>
            <Glyph value="offset_7_3"/>
            <Glyph value="offset_8_3"/>
            <Glyph value="offset_9_3"/>
            <Glyph value="offset_a_3"/>
            <Glyph value="offset_b_3"/>
            <Glyph value="offset_c_3"/>
            <Glyph value="offset_d_3"/>
            <Glyph value="offset_e_3"/>
            <Glyph value="offset_f_3"/>
          </LookAheadCoverage>
          <LookAheadCoverage index="2">
            <Glyph value="offset_0_4"/>
            <Glyph value="offset_1_4"/>
            <Glyph value="offset_2_4"/>
            <Glyph value="offset_3_4"/>
            <Glyph value="offset_4_4"/>
            <Glyph value="offset_5_4"/>
            <Glyph value="offset_6_4"/>
            <Glyph value="offset_7_4"/>
            <Glyph value="offset_8_4"/>
            <Glyph value="offset_9_4"/>
            <Glyph value="offset_a_4"/>
            <Glyph value="offset_b_4"/>
            <Glyph value="offset_c_4"/>
            <Glyph value="offset_d_4"/>
            <Glyph value="offset_e_4"/>
            <Glyph value="offset_f_4"/>
          </LookAheadCoverage>
          <PosLookupRecord index="0">
            <SequenceIndex value="0"/>
            <LookupListIndex value="1"/>
          </PosLookupRecord>
        </ChainContextPos>
      </Lookup>
      <Lookup index="1">
        <LookupType value="1"/>
        <LookupFlag value="0"/>
        <SinglePos index="0" Format="1">
          <Coverage>
            <Glyph value="offset_0_4"/>
            <Glyph value="offset_1_4"/>
            <Glyph value="offset_2_4"/>
            <Glyph value="offset_3_4"/>
            <Glyph value="offset_4_4"/>
            <Glyph value="offset_5_4"/>
            <Glyph value="offset_6_4"/>
            <Glyph value="offset_7_4"/>
            <Glyph value="offset_8_4"/>
            <Glyph value="offset_9_4"/>
            <Glyph value="offset_a_4"/>
            <Glyph value="offset_b_4"/>
            <Glyph value="offset_c_4"/>
            <Glyph value="offset_d_4"/>
            <Glyph value="offset_e_4"/>
            <Glyph value="offset_f_4"/>
          </Coverage>
          <ValueFormat value="5"/>
          <Value XPlacement="-2040" XAdvance="0"/>
        </SinglePos>
        <SinglePos index="1" Format="1">
          <Coverage>
            <Glyph value="offset_0_3"/>
            <Glyph value="offset_1_3"/>
            <Glyph value="offset_2_3"/>
            <Glyph value="offset_3_3"/>
            <Glyph value="offset_4_3"/>
            <Glyph value="offset_5_3"/>
            <Glyph value="offset_6_3"/>
            <Glyph value="offset_7_3"/>
            <Glyph value="offset_8_3"/>
            <Glyph value="offset_9_3"/>
            <Glyph value="offset_a_3"/>
            <Glyph value="offset_b_3"/>
            <Glyph value="offset_c_3"/>
            <Glyph value="offset_d_3"/>
            <Glyph value="offset_e_3"/>
            <Glyph value="offset_f_3"/>
          </Coverage>
          <ValueFormat value="5"/>
          <Value XPlacement="-2040" XAdvance="0"/>
        </SinglePos>
        <SinglePos index="2" Format="1">
          <Coverage>
            <Glyph value="offset_0_2"/>
            <Glyph value="offset_1_2"/>
            <Glyph value="offset_2_2"/>
            <Glyph value="offset_3_2"/>
            <Glyph value="offset_4_2"/>
            <Glyph value="offset_5_2"/>
            <Glyph value="offset_6_2"/>
            <Glyph value="offset_7_2"/>
            <Glyph value="offset_8_2"/>
            <Glyph value="offset_9_2"/>
            <Glyph value="offset_a_2"/>
            <Glyph value="offset_b_2"/>
            <Glyph value="offset_c_2"/>
            <Glyph value="offset_d_2"/>
            <Glyph value="offset_e_2"/>
            <Glyph value="offset_f_2"/>
          </Coverage>
          <ValueFormat value="5"/>
          <Value XPlacement="2040" XAdvance="0"/>
        </SinglePos>
        <SinglePos index="3" Format="1">
          <Coverage>
            <Glyph value="offset_0"/>
            <Glyph value="offset_1"/>
            <Glyph value="offset_2"/>
            <Glyph value="offset_3"/>
            <Glyph value="offset_4"/>
            <Glyph value="offset_5"/>
            <Glyph value="offset_6"/>
            <Glyph value="offset_7"/>
            <Glyph value="offset_8"/>
            <Glyph value="offset_9"/>
            <Glyph value="offset_a"/>
            <Glyph value="offset_b"/>
            <Glyph value="offset_c"/>
            <Glyph value="offset_d"/>
            <Glyph value="offset_e"/>
            <Glyph value="offset_f"/>
          </Coverage>
          <ValueFormat value="5"/>
          <Value XPlacement="2040" XAdvance="0"/>
        </SinglePos>
      </Lookup>
    </LookupList>
</GPOS>
"""

    gsub_tmpl = """
<GSUB>
  <Version value="0x00010000"/>
  <ScriptList>
    <ScriptRecord index="0">
      <ScriptTag value="latn"/>
      <Script>
        <DefaultLangSys>
          <ReqFeatureIndex value="0"/>
          <FeatureIndex index="0" value="0"/>
        </DefaultLangSys>
      </Script>
    </ScriptRecord>
  </ScriptList>
  <FeatureList>
    <FeatureRecord index="0">
      <FeatureTag value="calt"/>
      <Feature>
      </Feature>
    </FeatureRecord>
  </FeatureList>
  <LookupList>
  </LookupList>
</GSUB>
"""

    tmpl_chain_context_subst_init_fini_lit = """
    <Lookup index="__i__">
      <LookupType value="7"/>
      <LookupFlag value="0"/>
      <ExtensionSubst index="0" Format="1">
          <ExtensionLookupType value="6"/>
          <ChainContextSubst Format="3">
          </ChainContextSubst>
      </ExtensionSubst>
      <ExtensionSubst index="1" Format="1">
        <ExtensionLookupType value="6"/>
        <ChainContextSubst Format="1">
        </ChainContextSubst>
      </ExtensionSubst>
    </Lookup>
"""

    tmpl0_chain_context_subst_init_lit = """
    <Lookup index="__i__">
      <LookupType value="7"/>
      <LookupFlag value="0"/>
      <ExtensionSubst index="0" Format="1">
          <ExtensionLookupType value="6"/>
          <ChainContextSubst Format="3">
              <BacktrackCoverage index="0">
                  <Glyph value="zero"/>
                  <Glyph value="one"/>
                  <Glyph value="two"/>
                  <Glyph value="three"/>
                  <Glyph value="four"/>
                  <Glyph value="five"/>
                  <Glyph value="six"/>
                  <Glyph value="seven"/>
                  <Glyph value="eight"/>
                  <Glyph value="nine"/>
                  <Glyph value="a"/>
                  <Glyph value="b"/>
                  <Glyph value="c"/>
                  <Glyph value="d"/>
                  <Glyph value="e"/>
                  <Glyph value="f"/>
              </BacktrackCoverage>
              <BacktrackCoverage index="1">
                  <Glyph value="zero"/>
                  <Glyph value="one"/>
                  <Glyph value="two"/>
                  <Glyph value="three"/>
                  <Glyph value="four"/>
                  <Glyph value="five"/>
                  <Glyph value="six"/>
                  <Glyph value="seven"/>
                  <Glyph value="eight"/>
                  <Glyph value="nine"/>
                  <Glyph value="a"/>
                  <Glyph value="b"/>
                  <Glyph value="c"/>
                  <Glyph value="d"/>
                  <Glyph value="e"/>
                  <Glyph value="f"/>
              </BacktrackCoverage>
              <BacktrackCoverage index="2">
                  <Glyph value="uni2008"/>
                  <Glyph value="uni2009"/>
                  <Glyph value="uni200A"/>
                  <Glyph value="uni200B"/>
              </BacktrackCoverage>
              <InputCoverage index="0">
                  <Glyph value="zero"/>
                  <Glyph value="one"/>
                  <Glyph value="two"/>
                  <Glyph value="three"/>
                  <Glyph value="four"/>
                  <Glyph value="five"/>
                  <Glyph value="six"/>
                  <Glyph value="seven"/>
                  <Glyph value="eight"/>
                  <Glyph value="nine"/>
                  <Glyph value="a"/>
                  <Glyph value="b"/>
                  <Glyph value="c"/>
                  <Glyph value="d"/>
                  <Glyph value="e"/>
                  <Glyph value="f"/>
              </InputCoverage>
          </ChainContextSubst>
      </ExtensionSubst>
      <ExtensionSubst index="1" Format="1">
          <ExtensionLookupType value="6"/>
          <ChainContextSubst Format="3">
              <BacktrackCoverage index="0">
                  <Glyph value="zero"/>
                  <Glyph value="one"/>
                  <Glyph value="two"/>
                  <Glyph value="three"/>
                  <Glyph value="four"/>
                  <Glyph value="five"/>
                  <Glyph value="six"/>
                  <Glyph value="seven"/>
                  <Glyph value="eight"/>
                  <Glyph value="nine"/>
                  <Glyph value="a"/>
                  <Glyph value="b"/>
                  <Glyph value="c"/>
                  <Glyph value="d"/>
                  <Glyph value="e"/>
                  <Glyph value="f"/>
              </BacktrackCoverage>
              <BacktrackCoverage index="1">
                  <Glyph value="uni2008"/>
                  <Glyph value="uni2009"/>
                  <Glyph value="uni200A"/>
                  <Glyph value="uni200B"/>
              </BacktrackCoverage>
              <InputCoverage index="0">
                  <Glyph value="zero"/>
                  <Glyph value="one"/>
                  <Glyph value="two"/>
                  <Glyph value="three"/>
                  <Glyph value="four"/>
                  <Glyph value="five"/>
                  <Glyph value="six"/>
                  <Glyph value="seven"/>
                  <Glyph value="eight"/>
                  <Glyph value="nine"/>
                  <Glyph value="a"/>
                  <Glyph value="b"/>
                  <Glyph value="c"/>
                  <Glyph value="d"/>
                  <Glyph value="e"/>
                  <Glyph value="f"/>
              </InputCoverage>
          </ChainContextSubst>
      </ExtensionSubst>
      <ExtensionSubst index="2" Format="1">
          <ExtensionLookupType value="6"/>
          <ChainContextSubst Format="3">
              <BacktrackCoverage index="0">
                  <Glyph value="uni2008"/>
                  <Glyph value="uni2009"/>
                  <Glyph value="uni200A"/>
                  <Glyph value="uni200B"/>
              </BacktrackCoverage>
              <InputCoverage index="0">
                  <Glyph value="zero"/>
                  <Glyph value="one"/>
                  <Glyph value="two"/>
                  <Glyph value="three"/>
                  <Glyph value="four"/>
                  <Glyph value="five"/>
                  <Glyph value="six"/>
                  <Glyph value="seven"/>
                  <Glyph value="eight"/>
                  <Glyph value="nine"/>
                  <Glyph value="a"/>
                  <Glyph value="b"/>
                  <Glyph value="c"/>
                  <Glyph value="d"/>
                  <Glyph value="e"/>
                  <Glyph value="f"/>
              </InputCoverage>
          </ChainContextSubst>
      </ExtensionSubst>
      <ExtensionSubst index="3" Format="1">
        <ExtensionLookupType value="6"/>
        <ChainContextSubst Format="1">
          <Coverage>
          </Coverage>
        </ChainContextSubst>
      </ExtensionSubst>
    </Lookup>
"""

    tmpl_ligature_subst_init_lit = """
    <Lookup index="__i__">
      <LookupType value="7"/>
      <LookupFlag value="0"/>
      <ExtensionSubst index="0" Format="1">
        <ExtensionLookupType value="4"/>
        <LigatureSubst>
        </LigatureSubst>
      </ExtensionSubst>
    </Lookup>
"""

    tmpl0_multiple_subst_offset1_delim = """
    <Lookup index="__i__">
      <LookupType value="2"/>
      <LookupFlag value="0"/>
      <MultipleSubst index="0">
      </MultipleSubst>
    </Lookup>
"""

    tmpl0_ligature_subst_offset1_value = """
    <Lookup index="__i__">
      <LookupType value="4"/>
      <LookupFlag value="0"/>
      <LigatureSubst index="0">
      </LigatureSubst>
    </Lookup>
"""

    tmpl1_chain_context_subst_offset2_lit = """
    <Lookup index="__i__">
        <LookupType value="7"/>
        <LookupFlag value="0"/>
        <ExtensionSubst index="0" Format="1">
            <ExtensionLookupType value="6"/>
            <ChainContextSubst Format="2">
                <Coverage>
                  <Glyph value="offset_0_2"/>
                  <Glyph value="offset_1_2"/>
                  <Glyph value="offset_2_2"/>
                  <Glyph value="offset_3_2"/>
                  <Glyph value="offset_4_2"/>
                  <Glyph value="offset_5_2"/>
                  <Glyph value="offset_6_2"/>
                  <Glyph value="offset_7_2"/>
                  <Glyph value="offset_8_2"/>
                  <Glyph value="offset_9_2"/>
                  <Glyph value="offset_a_2"/>
                  <Glyph value="offset_b_2"/>
                  <Glyph value="offset_c_2"/>
                  <Glyph value="offset_d_2"/>
                  <Glyph value="offset_e_2"/>
                  <Glyph value="offset_f_2"/>
                </Coverage>
                <BacktrackClassDef>
                  <ClassDef glyph="uni2008" class="2"/>
                  <ClassDef glyph="uni2009" class="2"/>
                  <ClassDef glyph="uni200A" class="2"/>
                  <ClassDef glyph="uni200B" class="2"/>
                  <ClassDef glyph="offset_0" class="2"/>
                  <ClassDef glyph="offset_1" class="2"/>
                  <ClassDef glyph="offset_2" class="2"/>
                  <ClassDef glyph="offset_3" class="2"/>
                  <ClassDef glyph="offset_4" class="2"/>
                  <ClassDef glyph="offset_5" class="2"/>
                  <ClassDef glyph="offset_6" class="2"/>
                  <ClassDef glyph="offset_7" class="2"/>
                  <ClassDef glyph="offset_8" class="2"/>
                  <ClassDef glyph="offset_9" class="2"/>
                  <ClassDef glyph="offset_a" class="2"/>
                  <ClassDef glyph="offset_b" class="2"/>
                  <ClassDef glyph="offset_c" class="2"/>
                  <ClassDef glyph="offset_d" class="2"/>
                  <ClassDef glyph="offset_e" class="2"/>
                  <ClassDef glyph="offset_f" class="2"/>
                </BacktrackClassDef>
                <InputClassDef>
                  <ClassDef glyph="offset_0_2" class="1"/>
                  <ClassDef glyph="offset_1_2" class="1"/>
                  <ClassDef glyph="offset_2_2" class="1"/>
                  <ClassDef glyph="offset_3_2" class="1"/>
                  <ClassDef glyph="offset_4_2" class="1"/>
                  <ClassDef glyph="offset_5_2" class="1"/>
                  <ClassDef glyph="offset_6_2" class="1"/>
                  <ClassDef glyph="offset_7_2" class="1"/>
                  <ClassDef glyph="offset_8_2" class="1"/>
                  <ClassDef glyph="offset_9_2" class="1"/>
                  <ClassDef glyph="offset_a_2" class="1"/>
                  <ClassDef glyph="offset_b_2" class="1"/>
                  <ClassDef glyph="offset_c_2" class="1"/>
                  <ClassDef glyph="offset_d_2" class="1"/>
                  <ClassDef glyph="offset_e_2" class="1"/>
                  <ClassDef glyph="offset_f_2" class="1"/>
                </InputClassDef>
                <ChainSubClassSet index="0" empty="1"/>
                <ChainSubClassSet index="1">
                  <ChainSubClassRule index="0">
                    <Backtrack index="0" value="2"/>
                    <Backtrack index="1" value="1"/>
                    <SubstLookupRecord index="0">
                      <SequenceIndex value="0"/>
                      <LookupListIndex value="__i2__"/>
                    </SubstLookupRecord>
                  </ChainSubClassRule>
                </ChainSubClassSet>
            </ChainContextSubst>
        </ExtensionSubst>
    </Lookup>
"""

    tmpl1_chain_context_subst_offset4_lit = """
    <Lookup index="__i__">
        <LookupType value="7"/>
        <LookupFlag value="0"/>
        <ExtensionSubst index="0" Format="1">
            <ExtensionLookupType value="6"/>
            <ChainContextSubst Format="2">
                <Coverage>
                  <Glyph value="offset_0_4"/>
                  <Glyph value="offset_1_4"/>
                  <Glyph value="offset_2_4"/>
                  <Glyph value="offset_3_4"/>
                  <Glyph value="offset_4_4"/>
                  <Glyph value="offset_5_4"/>
                  <Glyph value="offset_6_4"/>
                  <Glyph value="offset_7_4"/>
                  <Glyph value="offset_8_4"/>
                  <Glyph value="offset_9_4"/>
                  <Glyph value="offset_a_4"/>
                  <Glyph value="offset_b_4"/>
                  <Glyph value="offset_c_4"/>
                  <Glyph value="offset_d_4"/>
                  <Glyph value="offset_e_4"/>
                  <Glyph value="offset_f_4"/>
                </Coverage>
                <BacktrackClassDef>
                  <ClassDef glyph="uni2008" class="2"/>
                  <ClassDef glyph="uni2009" class="2"/>
                  <ClassDef glyph="uni200A" class="2"/>
                  <ClassDef glyph="uni200B" class="2"/>
                  <ClassDef glyph="offset_0" class="4"/>
                  <ClassDef glyph="offset_1" class="4"/>
                  <ClassDef glyph="offset_2" class="4"/>
                  <ClassDef glyph="offset_3" class="4"/>
                  <ClassDef glyph="offset_4" class="4"/>
                  <ClassDef glyph="offset_5" class="4"/>
                  <ClassDef glyph="offset_6" class="4"/>
                  <ClassDef glyph="offset_7" class="4"/>
                  <ClassDef glyph="offset_8" class="4"/>
                  <ClassDef glyph="offset_9" class="4"/>
                  <ClassDef glyph="offset_a" class="4"/>
                  <ClassDef glyph="offset_b" class="4"/>
                  <ClassDef glyph="offset_c" class="4"/>
                  <ClassDef glyph="offset_d" class="4"/>
                  <ClassDef glyph="offset_e" class="4"/>
                  <ClassDef glyph="offset_f" class="4"/>
                  <ClassDef glyph="offset_0_2" class="3"/>
                  <ClassDef glyph="offset_1_2" class="3"/>
                  <ClassDef glyph="offset_2_2" class="3"/>
                  <ClassDef glyph="offset_3_2" class="3"/>
                  <ClassDef glyph="offset_4_2" class="3"/>
                  <ClassDef glyph="offset_5_2" class="3"/>
                  <ClassDef glyph="offset_6_2" class="3"/>
                  <ClassDef glyph="offset_7_2" class="3"/>
                  <ClassDef glyph="offset_8_2" class="3"/>
                  <ClassDef glyph="offset_9_2" class="3"/>
                  <ClassDef glyph="offset_a_2" class="3"/>
                  <ClassDef glyph="offset_b_2" class="3"/>
                  <ClassDef glyph="offset_c_2" class="3"/>
                  <ClassDef glyph="offset_d_2" class="3"/>
                  <ClassDef glyph="offset_e_2" class="3"/>
                  <ClassDef glyph="offset_f_2" class="3"/>
                  <ClassDef glyph="offset_0_3" class="2"/>
                  <ClassDef glyph="offset_1_3" class="2"/>
                  <ClassDef glyph="offset_2_3" class="2"/>
                  <ClassDef glyph="offset_3_3" class="2"/>
                  <ClassDef glyph="offset_4_3" class="2"/>
                  <ClassDef glyph="offset_5_3" class="2"/>
                  <ClassDef glyph="offset_6_3" class="2"/>
                  <ClassDef glyph="offset_7_3" class="2"/>
                  <ClassDef glyph="offset_8_3" class="2"/>
                  <ClassDef glyph="offset_9_3" class="2"/>
                  <ClassDef glyph="offset_a_3" class="2"/>
                  <ClassDef glyph="offset_b_3" class="2"/>
                  <ClassDef glyph="offset_c_3" class="2"/>
                  <ClassDef glyph="offset_d_3" class="2"/>
                  <ClassDef glyph="offset_e_3" class="2"/>
                  <ClassDef glyph="offset_f_3" class="2"/>
                </BacktrackClassDef>
                <InputClassDef>
                  <ClassDef glyph="offset_0_4" class="1"/>
                  <ClassDef glyph="offset_1_4" class="1"/>
                  <ClassDef glyph="offset_2_4" class="1"/>
                  <ClassDef glyph="offset_3_4" class="1"/>
                  <ClassDef glyph="offset_4_4" class="1"/>
                  <ClassDef glyph="offset_5_4" class="1"/>
                  <ClassDef glyph="offset_6_4" class="1"/>
                  <ClassDef glyph="offset_7_4" class="1"/>
                  <ClassDef glyph="offset_8_4" class="1"/>
                  <ClassDef glyph="offset_9_4" class="1"/>
                  <ClassDef glyph="offset_a_4" class="1"/>
                  <ClassDef glyph="offset_b_4" class="1"/>
                  <ClassDef glyph="offset_c_4" class="1"/>
                  <ClassDef glyph="offset_d_4" class="1"/>
                  <ClassDef glyph="offset_e_4" class="1"/>
                  <ClassDef glyph="offset_f_4" class="1"/>
                </InputClassDef>
                <ChainSubClassSet index="0" empty="1"/>
                <ChainSubClassSet index="1">
                  <ChainSubClassRule index="0">
                    <Backtrack index="0" value="2"/>
                    <Backtrack index="1" value="3"/>
                    <Backtrack index="2" value="4"/>
                    <Backtrack index="3" value="1"/>
                    <SubstLookupRecord index="0">
                      <SequenceIndex value="0"/>
                      <LookupListIndex value="__i2__"/>
                    </SubstLookupRecord>
                  </ChainSubClassRule>
                </ChainSubClassSet>
            </ChainContextSubst>
        </ExtensionSubst>
    </Lookup>
"""

    tmpl1_multiple_subst_offset2_lit = """
    <Lookup index="__i__">
        <LookupType value="7"/>
        <LookupFlag value="0"/>
        <ExtensionSubst index="0" Format="1">
            <ExtensionLookupType value="2"/>
            <MultipleSubst>
            </MultipleSubst>
        </ExtensionSubst>
    </Lookup>
"""

    tmpl2_chain_context_subst_offset3_delim = """
    <Lookup index="__i__">
        <LookupType value="7"/>
        <LookupFlag value="0"/>
        <ExtensionSubst index="0" Format="1">
            <ExtensionLookupType value="6"/>
            <ChainContextSubst Format="2">
                <Coverage>
                  <Glyph value="offset_0_2"/>
                  <Glyph value="offset_1_2"/>
                  <Glyph value="offset_2_2"/>
                  <Glyph value="offset_3_2"/>
                  <Glyph value="offset_4_2"/>
                  <Glyph value="offset_5_2"/>
                  <Glyph value="offset_6_2"/>
                  <Glyph value="offset_7_2"/>
                  <Glyph value="offset_8_2"/>
                  <Glyph value="offset_9_2"/>
                  <Glyph value="offset_a_2"/>
                  <Glyph value="offset_b_2"/>
                  <Glyph value="offset_c_2"/>
                  <Glyph value="offset_d_2"/>
                  <Glyph value="offset_e_2"/>
                  <Glyph value="offset_f_2"/>
                </Coverage>
                <BacktrackClassDef>
                  <ClassDef glyph="uni2008" class="2"/>
                  <ClassDef glyph="uni2009" class="2"/>
                  <ClassDef glyph="uni200A" class="2"/>
                  <ClassDef glyph="uni200B" class="2"/>
                  <ClassDef glyph="offset_0" class="2"/>
                  <ClassDef glyph="offset_1" class="2"/>
                  <ClassDef glyph="offset_2" class="2"/>
                  <ClassDef glyph="offset_3" class="2"/>
                  <ClassDef glyph="offset_4" class="2"/>
                  <ClassDef glyph="offset_5" class="2"/>
                  <ClassDef glyph="offset_6" class="2"/>
                  <ClassDef glyph="offset_7" class="2"/>
                  <ClassDef glyph="offset_8" class="2"/>
                  <ClassDef glyph="offset_9" class="2"/>
                  <ClassDef glyph="offset_a" class="2"/>
                  <ClassDef glyph="offset_b" class="2"/>
                  <ClassDef glyph="offset_c" class="2"/>
                  <ClassDef glyph="offset_d" class="2"/>
                  <ClassDef glyph="offset_e" class="2"/>
                  <ClassDef glyph="offset_f" class="2"/>
                </BacktrackClassDef>
                <InputClassDef>
                  <ClassDef glyph="offset_0_2" class="1"/>
                  <ClassDef glyph="offset_1_2" class="1"/>
                  <ClassDef glyph="offset_2_2" class="1"/>
                  <ClassDef glyph="offset_3_2" class="1"/>
                  <ClassDef glyph="offset_4_2" class="1"/>
                  <ClassDef glyph="offset_5_2" class="1"/>
                  <ClassDef glyph="offset_6_2" class="1"/>
                  <ClassDef glyph="offset_7_2" class="1"/>
                  <ClassDef glyph="offset_8_2" class="1"/>
                  <ClassDef glyph="offset_9_2" class="1"/>
                  <ClassDef glyph="offset_a_2" class="1"/>
                  <ClassDef glyph="offset_b_2" class="1"/>
                  <ClassDef glyph="offset_c_2" class="1"/>
                  <ClassDef glyph="offset_d_2" class="1"/>
                  <ClassDef glyph="offset_e_2" class="1"/>
                  <ClassDef glyph="offset_f_2" class="1"/>
                </InputClassDef>
                <ChainSubClassSet index="0" empty="1"/>
                <ChainSubClassSet index="1">
                  <ChainSubClassRule index="0">
                    <Backtrack index="0" value="2"/>
                    <Backtrack index="1" value="1"/>
                    <SubstLookupRecord index="0">
                      <SequenceIndex value="0"/>
                      <LookupListIndex value="__i2__"/>
                    </SubstLookupRecord>
                  </ChainSubClassRule>
                </ChainSubClassSet>
            </ChainContextSubst>
        </ExtensionSubst>
    </Lookup>
"""

    tmpl_chain_context_subst_signed = """
    <Lookup index="__i__">
      <LookupType value="7"/>
      <LookupFlag value="0"/>
      <ExtensionSubst index="0" Format="1">
          <ExtensionLookupType value="6"/>
          <ChainContextSubst Format="2">
              <Coverage>
              </Coverage>
              <BacktrackClassDef index="0">
              </BacktrackClassDef>
              <InputClassDef index="0">
              </InputClassDef>
              <LookAheadClassDef index="0">
              </LookAheadClassDef>
              <ChainSubClassSet index="0" empty="1"/>
              <ChainSubClassSet index="1">
                <ChainSubClassRule index="0">
                  <Backtrack index="0" value="1"/>
                  <LookAhead index="0" value="1"/>
                  <SubstLookupRecord index="0">
                    <SequenceIndex value="0"/>
                    <LookupListIndex value="__i2__"/>
                  </SubstLookupRecord>
                </ChainSubClassRule>
              </ChainSubClassSet>
          </ChainContextSubst>
      </ExtensionSubst>
    </Lookup>
"""

    tmpl_multiple_subst_signed = """
        <Lookup index="__i__">
            <LookupType value="2"/>
            <LookupFlag value="0"/>
            <MultipleSubst index="0">
            </MultipleSubst>
        </Lookup>
"""

    tmpl_chain_context_subst_signed_offset_2 = """
        <Lookup index="__i__">
            <LookupType value="7"/>
            <LookupFlag value="0"/>
            <ExtensionSubst index="0" Format="1">
                <ExtensionLookupType value="6"/>
                <ChainContextSubst Format="2">
                    <Coverage>
                        <Glyph value="offset_0_2"/>
                        <Glyph value="offset_1_2"/>
                        <Glyph value="offset_2_2"/>
                        <Glyph value="offset_3_2"/>
                        <Glyph value="offset_4_2"/>
                        <Glyph value="offset_5_2"/>
                        <Glyph value="offset_6_2"/>
                        <Glyph value="offset_7_2"/>
                        <Glyph value="offset_8_2"/>
                        <Glyph value="offset_9_2"/>
                        <Glyph value="offset_a_2"/>
                        <Glyph value="offset_b_2"/>
                        <Glyph value="offset_c_2"/>
                        <Glyph value="offset_d_2"/>
                        <Glyph value="offset_e_2"/>
                        <Glyph value="offset_f_2"/>
                    </Coverage>
                    <BacktrackClassDef index="0">
                        <ClassDef glyph="offset_0_s" class="1"/>
                        <ClassDef glyph="offset_1_s" class="1"/>
                        <ClassDef glyph="offset_2_s" class="1"/>
                        <ClassDef glyph="offset_3_s" class="1"/>
                        <ClassDef glyph="offset_4_s" class="1"/>
                        <ClassDef glyph="offset_5_s" class="1"/>
                        <ClassDef glyph="offset_6_s" class="1"/>
                        <ClassDef glyph="offset_7_s" class="1"/>
                        <ClassDef glyph="offset_8_s" class="1"/>
                        <ClassDef glyph="offset_9_s" class="1"/>
                        <ClassDef glyph="offset_a_s" class="1"/>
                        <ClassDef glyph="offset_b_s" class="1"/>
                        <ClassDef glyph="offset_c_s" class="1"/>
                        <ClassDef glyph="offset_d_s" class="1"/>
                        <ClassDef glyph="offset_e_s" class="1"/>
                        <ClassDef glyph="offset_f_s" class="1"/>
                    </BacktrackClassDef>
                    <InputClassDef index="0">
                        <ClassDef glyph="offset_0_2" class="1"/>
                        <ClassDef glyph="offset_1_2" class="1"/>
                        <ClassDef glyph="offset_2_2" class="1"/>
                        <ClassDef glyph="offset_3_2" class="1"/>
                        <ClassDef glyph="offset_4_2" class="1"/>
                        <ClassDef glyph="offset_5_2" class="1"/>
                        <ClassDef glyph="offset_6_2" class="1"/>
                        <ClassDef glyph="offset_7_2" class="1"/>
                        <ClassDef glyph="offset_8_2" class="1"/>
                        <ClassDef glyph="offset_9_2" class="1"/>
                        <ClassDef glyph="offset_a_2" class="1"/>
                        <ClassDef glyph="offset_b_2" class="1"/>
                        <ClassDef glyph="offset_c_2" class="1"/>
                        <ClassDef glyph="offset_d_2" class="1"/>
                        <ClassDef glyph="offset_e_2" class="1"/>
                        <ClassDef glyph="offset_f_2" class="1"/>
                    </InputClassDef>
                    <ChainSubClassSet index="0" empty="1"/>
                    <ChainSubClassSet index="1">
                        <ChainSubClassRule index="0">
                            <Backtrack index="0" value="1"/>
                            <Backtrack index="1" value="2"/>
                            <SubstLookupRecord index="0">
                                <SequenceIndex value="0"/>
                                <LookupListIndex value="__i2__"/>
                            </SubstLookupRecord>
                        </ChainSubClassRule>
                    </ChainSubClassSet>
                </ChainContextSubst>
            </ExtensionSubst>
        </Lookup>
"""

    tmpl_multiple_subst_signed_minus_offset_2 = """
        <Lookup index="__i__">
            <LookupType value="2"/>
            <LookupFlag value="0"/>
            <MultipleSubst index="0">
                <Substitution in="offset_0_2" out="offset_0_s2"/>
                <Substitution in="offset_1_2" out="offset_f_s2"/>
                <Substitution in="offset_2_2" out="offset_e_s2"/>
                <Substitution in="offset_3_2" out="offset_d_s2"/>
                <Substitution in="offset_4_2" out="offset_c_s2"/>
                <Substitution in="offset_5_2" out="offset_b_s2"/>
                <Substitution in="offset_6_2" out="offset_a_s2"/>
                <Substitution in="offset_7_2" out="offset_9_s2"/>
                <Substitution in="offset_8_2" out="offset_8_s2"/>
                <Substitution in="offset_9_2" out="offset_7_s2"/>
                <Substitution in="offset_a_2" out="offset_6_s2"/>
                <Substitution in="offset_b_2" out="offset_5_s2"/>
                <Substitution in="offset_c_2" out="offset_4_s2"/>
                <Substitution in="offset_d_2" out="offset_3_s2"/>
                <Substitution in="offset_e_2" out="offset_2_s2"/>
                <Substitution in="offset_f_2" out="offset_1_s2"/>
            </MultipleSubst>
        </Lookup>
"""

    tmpl_multiple_subst_signed_plus_offset_2 = """
        <Lookup index="__i__">
            <LookupType value="2"/>
            <LookupFlag value="0"/>
            <MultipleSubst index="0">
                <Substitution in="offset_0_2" out="offset_0_s2"/>
                <Substitution in="offset_1_2" out="offset_1_s2"/>
                <Substitution in="offset_2_2" out="offset_2_s2"/>
                <Substitution in="offset_3_2" out="offset_3_s2"/>
                <Substitution in="offset_4_2" out="offset_4_s2"/>
                <Substitution in="offset_5_2" out="offset_5_s2"/>
                <Substitution in="offset_6_2" out="offset_6_s2"/>
                <Substitution in="offset_7_2" out="offset_7_s2"/>
                <Substitution in="offset_8_2" out="offset_8_s2"/>
                <Substitution in="offset_9_2" out="offset_9_s2"/>
                <Substitution in="offset_a_2" out="offset_a_s2"/>
                <Substitution in="offset_b_2" out="offset_b_s2"/>
                <Substitution in="offset_c_2" out="offset_c_s2"/>
                <Substitution in="offset_d_2" out="offset_d_s2"/>
                <Substitution in="offset_e_2" out="offset_e_s2"/>
                <Substitution in="offset_f_2" out="offset_f_s2"/>
            </MultipleSubst>
        </Lookup>
"""

    soup = BeautifulSoup(gsub_tmpl, features="xml")

    seen_lookup_ambiguous = {}
    seen_lookup_init_fini = {}
    seen_lookup_init_fini_mappings = {}
    seen_lookup1_glyph_names = set()
    emitLookup1 = EmitLookupLigatureSubst()
    emitLookup2 = EmitLookupMultipleSubst()
    emitLookup3 = EmitLookupLigatureSubst()
    emitLookup4 = EmitLookupMultipleSubst()
    emitLookup5 = EmitLookupLigatureSubst()
    seen_lookup6_suffixes = {}
    seen_lookup8_glyph_names = set()
    emitLookup9 = EmitLookupMultipleSubst()
    emitLookup10 = EmitLookupLigatureSubst()
    emitLookup11 = EmitLookupMultipleSubst()
    emitLookup12 = EmitLookupLigatureSubst()
    for glyph_chain in glyph_chains:
        logging.debug(glyph_chain)

        init_fini_joined = ",".join(
            [" ".join(glyph_chain[0].asms), " ".join(glyph_chain[-1].asms) if len(glyph_chain) > 1 and not glyph_chain[-1].is_offset else ""]
        )
        current_lookup1_glyph_name = None
        glyph_chain_offset_i = 0
        for glyph in glyph_chain:
            is_first_asm = True
            if glyph.lookup_i == 0:
                ligature_components = []
                ligature_components_key = None
                for asm in glyph.asms:
                    current_lookup1_glyph_name = glyph.name
                    # HACK: sort after splits doesn't guarantee counter order, but first one to assign is correct...
                    if current_lookup1_glyph_name not in seen_lookup_init_fini_mappings:
                        seen_lookup_init_fini_mappings[current_lookup1_glyph_name] = init_fini_joined
                    seen_lookup1_glyph_names.add(glyph.name)
                    nibble0 = digit_to_name(asm[0])
                    nibble1 = digit_to_name(asm[1])
                    if is_first_asm:
                        ligature_components_key = nibble0
                        if (
                            ligature_components_key
                            not in emitLookup1.ligature_set_glyphs
                        ):
                            emitLookup1.ligature_set_glyphs[ligature_components_key] = (
                                OrderedDict()
                            )
                    else:
                        ligature_components.append(nibble0)
                    ligature_components.append(nibble1)
                    is_first_asm = False

                ligature_components_joined = ",".join(ligature_components)
                if ligature_components_key not in seen_lookup_init_fini:
                    seen_lookup_init_fini[ligature_components_key] = {}
                if ligature_components_joined not in seen_lookup_init_fini[ligature_components_key]:
                    seen_lookup_init_fini[ligature_components_key][ligature_components_joined] = set()
                if ligature_components_joined in emitLookup1.ligature_set_glyphs[ligature_components_key] and init_fini_joined not in seen_lookup_init_fini[ligature_components_key][ligature_components_joined]:
                    if ligature_components_key not in seen_lookup_ambiguous:
                        seen_lookup_ambiguous[ligature_components_key] = {}
                    if ligature_components_joined not in seen_lookup_ambiguous[ligature_components_key]:
                        seen_lookup_ambiguous[ligature_components_key][ligature_components_joined] = set()

                    seen_lookup_ambiguous[ligature_components_key][ligature_components_joined].add(emitLookup1.ligature_set_glyphs[ligature_components_key][ligature_components_joined])
                    seen_lookup_ambiguous[ligature_components_key][ligature_components_joined].add(glyph.name)
                else:
                    emitLookup1.ligature_set_glyphs[ligature_components_key][ligature_components_joined] = glyph.name
                seen_lookup_init_fini[ligature_components_key][ligature_components_joined].add(init_fini_joined)
            elif glyph.lookup_i == 1:
                glyph_chain_offset_i += 1
                if glyph_chain_offset_i == 4:
                    # Matched 16-bit address
                    seen_lookup8_glyph_names.add(current_lookup1_glyph_name)
            elif glyph.lookup_i == 2:
                if glyph.name not in seen_lookup6_suffixes:
                    seen_lookup6_suffixes[glyph.name] = set()
                seen_lookup6_suffixes[glyph.name].add(current_lookup1_glyph_name)
            else:
                raise RuntimeError(f'TODO: lookup_i for "{glyph}".')

    effective_ligature_set_glyphs = {}
    for key in emitLookup1.ligature_set_glyphs:
        if key in seen_lookup_ambiguous:
            for key2 in emitLookup1.ligature_set_glyphs[key]:
                if key2 not in seen_lookup_ambiguous[key]:
                    if key not in effective_ligature_set_glyphs:
                        effective_ligature_set_glyphs[key] = {}
                    effective_ligature_set_glyphs[key][key2] = emitLookup1.ligature_set_glyphs[key][key2]
        else:
            effective_ligature_set_glyphs[key] = emitLookup1.ligature_set_glyphs[key]
    emitLookup1.ligature_set_glyphs = effective_ligature_set_glyphs

    logging.debug(seen_lookup1_glyph_names)
    logging.debug(emitLookup1.ligature_set_glyphs)
    logging.debug(seen_lookup_ambiguous)
    logging.debug(seen_lookup_init_fini)
    logging.debug(seen_lookup_init_fini_mappings)

    for name in seen_lookup1_glyph_names:
        emitLookup2.in_glyphs[name] = f"{name},uni200B"
    for i in range(0x10):
        emitLookup4.in_glyphs[f"offset_{i:01x}"] = f"offset_{i:01x},uni200A"
        emitLookup9.in_glyphs[f"offset_{i:01x}_2"] = f"offset_{i:01x}_2,uni2009"
        emitLookup11.in_glyphs[f"offset_{i:01x}_3"] = f"offset_{i:01x}_3,uni2008"

    emitLookup3.ligature_set_glyphs["uni200B"] = OrderedDict()
    emitLookup5.ligature_set_glyphs["uni200A"] = OrderedDict()
    emitLookup10.ligature_set_glyphs["uni2009"] = OrderedDict()
    emitLookup12.ligature_set_glyphs["uni2008"] = OrderedDict()
    for i in range(0x10):
        for j in range(0x10):
            emitLookup3.ligature_set_glyphs["uni200B"][
                digit_to_name(i)
            ] = f"offset_{i:01x}"
            emitLookup5.ligature_set_glyphs["uni200A"][
                digit_to_name(j)
            ] = f"offset_{j:01x}_2"
            emitLookup10.ligature_set_glyphs["uni2009"][
                digit_to_name(j)
            ] = f"offset_{j:01x}_3"
            emitLookup12.ligature_set_glyphs["uni2008"][
                digit_to_name(j)
            ] = f"offset_{j:01x}_4"

    lookups = []
    lookup_list_i = 0

    # ambiguous init fini case
    lookups, lookup_list_i = emit_chain_init_fini(
        seen_lookup_ambiguous,
        seen_lookup_init_fini_mappings,
        tmpl_chain_context_subst_init_fini_lit,
        tmpl_ligature_subst_init_lit,
        lookup_list_i
    )

    # general init fini case
    lookup0 = BeautifulSoup(
        tmpl0_chain_context_subst_init_lit.replace("__i__", str(lookup_list_i)),
        features="xml",
    )

    lookup0_tag_extension_subst0 = lookup0.find("ExtensionSubst", {"index": "0"})
    lookup0_tag_backtrack_coverage = lookup0_tag_extension_subst0.find(
        "BacktrackCoverage", {"index": "2"}
    )
    for name in seen_lookup1_glyph_names:
        tag_glyph = soup.new_tag(
            "Glyph",
            attrs={
                "value": name,
            },
        )
        lookup0_tag_backtrack_coverage.append(tag_glyph)
    lookup0_tag_extension_subst1 = lookup0.find("ExtensionSubst", {"index": "1"})
    lookup0_tag_backtrack_coverage = lookup0_tag_extension_subst1.find(
        "BacktrackCoverage", {"index": "1"}
    )
    for name in seen_lookup1_glyph_names:
        tag_glyph = soup.new_tag(
            "Glyph",
            attrs={
                "value": name,
            },
        )
        lookup0_tag_backtrack_coverage.append(tag_glyph)
    lookup0_tag_extension_subst2 = lookup0.find("ExtensionSubst", {"index": "2"})
    lookup0_tag_backtrack_coverage = lookup0_tag_extension_subst2.find(
        "BacktrackCoverage", {"index": "0"}
    )
    for name in seen_lookup1_glyph_names:
        tag_glyph = soup.new_tag(
            "Glyph",
            attrs={
                "value": name,
            },
        )
        lookup0_tag_backtrack_coverage.append(tag_glyph)

    lookup0_tag_extension_subst3 = lookup0.find("ExtensionSubst", {"index": "3"})
    lookup0_tag_chain_context_subst = lookup0_tag_extension_subst3.find(
        "ChainContextSubst"
    )
    lookup0_tag_coverage = lookup0_tag_chain_context_subst.find("Coverage")
    chain_set_i = 0
    for key in emitLookup1.ligature_set_glyphs.keys():
        tag_glyph = soup.new_tag(
            "Glyph",
            attrs={
                "value": key,
            },
        )
        lookup0_tag_coverage.append(tag_glyph)

        gsub_chain_tmpl = """
                      <ChainSubRuleSet index="__chain_set_i">
                        <ChainSubRule index="0">
                          <SubstLookupRecord index="0">
                            <SequenceIndex value="0"/>
                            <LookupListIndex value="__i2__"/>
                          </SubstLookupRecord>
                        </ChainSubRule>
                      </ChainSubRuleSet>"""
        gsub_chain_tmpl = gsub_chain_tmpl.replace("__chain_set_i", str(chain_set_i))
        gsub_chain_tmpl = gsub_chain_tmpl.replace("__i2__", str(lookup_list_i + 1))
        lookup0_tag_chain_context_subst.append(gsub_chain_tmpl)
        chain_set_i += 1
    lookups.append([lookup0, True])
    lookup_list_i += 1

    lookup1 = BeautifulSoup(
        tmpl_ligature_subst_init_lit.replace("__i__", str(lookup_list_i)),
        features="xml",
    )
    lookup1_tag_ligature_subst = lookup1.find("LigatureSubst")
    for key in emitLookup1.ligature_set_glyphs.keys():
        tag_ligature_set = soup.new_tag(
            "LigatureSet",
            attrs={
                "glyph": key,
            },
        )
        emitLookup1_ligature_set = emitLookup1.ligature_set_glyphs[key]
        for ligature_key in emitLookup1_ligature_set.keys():
            tag_ligature = soup.new_tag(
                "Ligature",
                attrs={
                    "components": ligature_key,
                    "glyph": emitLookup1_ligature_set[ligature_key],
                },
            )
            tag_ligature_set.append(tag_ligature)
        lookup1_tag_ligature_subst.append(tag_ligature_set)
    lookups.append([lookup1, False])
    lookup_list_i += 1

    lookup2 = BeautifulSoup(
        tmpl0_multiple_subst_offset1_delim.replace("__i__", str(lookup_list_i)),
        features="xml",
    )
    lookup2_tag_multiple_subst = lookup2.find("MultipleSubst")
    for key in emitLookup2.in_glyphs.keys():
        tag_substitution = soup.new_tag(
            "Substitution",
            attrs={
                "in": key,
                "out": emitLookup2.in_glyphs[key],
            },
        )
        lookup2_tag_multiple_subst.append(tag_substitution)
    lookups.append([lookup2, True])
    lookup_list_i += 1

    lookup3 = BeautifulSoup(
        tmpl0_ligature_subst_offset1_value.replace("__i__", str(lookup_list_i)),
        features="xml",
    )
    lookup3_tag_ligature_subst = lookup3.find("LigatureSubst")
    for key in emitLookup3.ligature_set_glyphs.keys():
        tag_ligature_set = soup.new_tag(
            "LigatureSet",
            attrs={
                "glyph": key,
            },
        )
        emitLookup3_ligature_set = emitLookup3.ligature_set_glyphs[key]
        for ligature_key in emitLookup3_ligature_set.keys():
            tag_ligature = soup.new_tag(
                "Ligature",
                attrs={
                    "components": ligature_key,
                    "glyph": emitLookup3_ligature_set[ligature_key],
                },
            )
            tag_ligature_set.append(tag_ligature)
        lookup3_tag_ligature_subst.append(tag_ligature_set)
    lookups.append([lookup3, True])
    lookup_list_i += 1

    lookups.append([emit_multiple_subst(emitLookup4, lookup_list_i), True])
    lookup_list_i += 1
    lookups.append([emit_ligature_subst(emitLookup5, lookup_list_i), True])
    lookup_list_i += 1

    lookup8 = BeautifulSoup(
        tmpl2_chain_context_subst_offset3_delim.replace(
            "__i__", str(lookup_list_i)
        ).replace("__i2__", str(lookup_list_i + 1)),
        features="xml",
    )
    lookup8_tag_extension_subst0 = lookup8.find("BacktrackClassDef")
    for name in seen_lookup8_glyph_names:
        tag_class_def = soup.new_tag(
            "ClassDef",
            attrs={
                "glyph": name,
                "class": "1",
            },
        )
        lookup8_tag_extension_subst0.append(tag_class_def)
    lookups.append([lookup8, True])
    lookup_list_i += 1

    # offset 2-3
    lookups.append([emit_multiple_subst(emitLookup9, lookup_list_i), False])
    lookup_list_i += 1
    lookups.append([emit_ligature_subst(emitLookup10, lookup_list_i), True])
    lookup_list_i += 1

    # offset 3-4
    lookups.append([emit_multiple_subst(emitLookup11, lookup_list_i), True])
    lookup_list_i += 1
    lookups.append([emit_ligature_subst(emitLookup12, lookup_list_i), True])
    lookup_list_i += 1

    # fini suffixes
    for suffix_key in seen_lookup6_suffixes.keys():
        prefixes_u8 = []
        prefixes_u16 = []
        for prefix in seen_lookup6_suffixes[suffix_key]:
            if prefix in seen_lookup8_glyph_names:
                prefixes_u16.append(prefix)
            else:
                prefixes_u8.append(prefix)

        if len(prefixes_u8) > 0:
            lookup6, lookup7 = emit_chain_suffixes(
                prefixes_u8,
                suffix_key,
                tmpl1_chain_context_subst_offset2_lit,
                tmpl1_multiple_subst_offset2_lit,
                "2",
            )
            lookups.append([lookup6, True])
            lookup_list_i += 1
            lookups.append([lookup7, False])
            lookup_list_i += 1

        if len(prefixes_u16) > 0:
            lookup6, lookup7 = emit_chain_suffixes(
                prefixes_u16,
                suffix_key,
                tmpl1_chain_context_subst_offset4_lit,
                tmpl1_multiple_subst_offset2_lit,
                "4",
            )
            lookups.append([lookup6, True])
            lookup_list_i += 1
            lookups.append([lookup7, False])
            lookup_list_i += 1

    # signed substs
    for signed_offset_2_list in [[0], list(range(1, 16))]:
        for signed_nibbles in [list(range(0, 8)), list(range(8, 16))]:

            lookup0 = BeautifulSoup(
                tmpl_chain_context_subst_signed.replace(
                    "__i__", str(lookup_list_i)
                ).replace("__i2__", str(lookup_list_i + 1)),
                features="xml",
            )
            lookup0_tag_extension_subst0 = lookup0.find(
                "ExtensionSubst", {"index": "0"}
            )
            lookup0_tag_coverage = lookup0_tag_extension_subst0.find("Coverage")
            lookup0_tag_input_coverage = lookup0_tag_extension_subst0.find(
                "InputClassDef", {"index": "0"}
            )
            for signed_nibble in signed_nibbles:
                tag_glyph = soup.new_tag(
                    "Glyph",
                    attrs={
                        "value": f"offset_{signed_nibble:01x}",
                    },
                )
                lookup0_tag_coverage.append(tag_glyph)
                tag_class_def = soup.new_tag(
                    "ClassDef",
                    attrs={
                        "glyph": f"offset_{signed_nibble:01x}",
                        "class": "1",
                    },
                )
                lookup0_tag_input_coverage.append(tag_class_def)

            lookup0_tag_backtrack_coverage = lookup0_tag_extension_subst0.find(
                "BacktrackClassDef", {"index": "0"}
            )
            for name in seen_signed_literals:
                tag_class_def = soup.new_tag(
                    "ClassDef",
                    attrs={
                        "glyph": name,
                        "class": "1",
                    },
                )
                lookup0_tag_backtrack_coverage.append(tag_class_def)

            lookup0_tag_lookahead_coverage = lookup0_tag_extension_subst0.find(
                "LookAheadClassDef", {"index": "0"}
            )
            for signed_offset_2 in signed_offset_2_list:
                tag_class_def = soup.new_tag(
                    "ClassDef",
                    attrs={
                        "glyph": f"offset_{signed_offset_2:01x}_2",
                        "class": "1",
                    },
                )
                lookup0_tag_lookahead_coverage.append(tag_class_def)
            lookups.append([lookup0, True])
            lookup_list_i += 1

            lookup2 = BeautifulSoup(
                tmpl_multiple_subst_signed.replace("__i__", str(lookup_list_i)),
                features="xml",
            )
            lookup2_tag_multiple_subst = lookup2.find("MultipleSubst")
            for signed_nibble in signed_nibbles:
                out_sign = "plus"
                out_signed_nibble = signed_nibble
                if signed_nibble > 7:
                    out_sign = "minus"
                    if signed_offset_2_list[0] > 0:
                        out_signed_nibble = 16 - (signed_nibble + 1)
                    else:
                        out_signed_nibble = 16 - signed_nibble
                tag_substitution = soup.new_tag(
                    "Substitution",
                    attrs={
                        "in": f"offset_{signed_nibble:01x}",
                        "out": f"{out_sign},offset_{out_signed_nibble:01x}_s",
                    },
                )
                lookup2_tag_multiple_subst.append(tag_substitution)
            lookups.append([lookup2, False])
            lookup_list_i += 1

    for sign in ["minus", "plus"]:
        lookup0 = BeautifulSoup(
            tmpl_chain_context_subst_signed_offset_2.replace(
                "__i__", str(lookup_list_i)
            ).replace("__i2__", str(lookup_list_i + 1)),
            features="xml",
        )
        lookup0_tag_backtrack_coverage = lookup0.find(
            "BacktrackClassDef", {"index": "0"}
        )
        tag_class_def = soup.new_tag(
            "ClassDef",
            attrs={
                "glyph": sign,
                "class": "2",
            },
        )
        lookup0_tag_backtrack_coverage.append(tag_class_def)
        lookups.append([lookup0, True])
        lookup_list_i += 1

        lookup0 = BeautifulSoup(
            (
                tmpl_multiple_subst_signed_minus_offset_2
                if sign == "minus"
                else tmpl_multiple_subst_signed_plus_offset_2
            ).replace("__i__", str(lookup_list_i)),
            features="xml",
        )
        lookups.append([lookup0, False])
        lookup_list_i += 1


    # ambi fini clear
    for name in seen_fini_with_asms:
        emitLookup5 = EmitLookupLigatureSubst()
        emitLookup5.ligature_set_glyphs[name] = OrderedDict()
        for i in range(0x10):
            for j in range(0x10):
                emitLookup5.ligature_set_glyphs[name][",".join([digit_to_name(i),digit_to_name(j)])] = name
        lookups.append([emit_ligature_subst(emitLookup5, lookup_list_i), True])
        lookup_list_i += 1

    # only add chain context lookups
    lookup_index = 0
    tag_feature = soup.find("Feature")
    tag_lookup_list = soup.find("LookupList")
    for lookup in lookups:
        emit_soup = lookup[0]
        lookup_value = emit_soup.find("Lookup")["index"]
        is_added_to_feature = lookup[1]
        if is_added_to_feature:
            tag_lookup_list_index = soup.new_tag(
                "LookupListIndex",
                attrs={
                    "index": lookup_index,
                    "value": lookup_value,
                },
            )
            tag_feature.append(tag_lookup_list_index)
            lookup_index += 1
        tag_lookup_list.append(emit_soup)

    # Finally, add tables to .ttx

    formatter = UnsortedAttributes(indent=4)
    gsub_updated = soup.prettify(formatter=formatter)
    gsub_updated = re.sub(
        re.escape('<?xml version="1.0" encoding="utf-8"?>'), "", gsub_updated
    )

    print("Adding tables.")
    ttx_files = Path("./fontcustom").glob("fontcustom_*.ttx")
    latest_ttx_file = max([f for f in ttx_files], key=lambda item: item.stat().st_mtime)
    with latest_ttx_file.open("r") as f:
        soup = BeautifulSoup(f.read(), features="xml")
        tag_ttfont = soup.find("ttFont")
        tag_ttfont.append(gpos_tmpl)
        tag_ttfont.append(gsub_updated)

    tag_hmtx = soup.find("hmtx")
    for mtx in tag_hmtx.find_all("mtx"):
        if mtx["name"].startswith("offset_"):
            prev_width = int(mtx["width"], 10)
            new_lsb = (1229 - prev_width) // 2
            new_width = prev_width + new_lsb
            mtx["lsb"] = str(new_lsb)
            mtx["width"] = str(new_width)

    with latest_ttx_file.open("w") as f:
        f.write(soup.prettify(formatter=formatter))

    print("Outputting ttf.")
    ttx_to_ttf()
