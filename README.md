# Z80 Sans

What's your favourite disassembler? Mine's a font:

https://github.com/user-attachments/assets/bb6ceb18-c2fd-40a9-be4f-202321a214d9

This font converts sequences of hexadecimal lowercase characters into disassembled Z80 instructions, by making extensive use of OpenType's [Glyph Substitution Table (GSUB)](https://learn.microsoft.com/en-us/typography/opentype/spec/gsub) and [Glyph Positioning Table (GPOS)](https://learn.microsoft.com/en-us/typography/opentype/spec/gpos).

If you just want to try it out, a copy is available under `./test/z80-sans.ttf`.

# Install

Tested on Debian GNU/Linux 12. Note that this Debian version ships with ruby version 3, while fontcustom was written for ruby version 2, and is incompatible with later versions (e.g. syntax errors). A ruby install also requires a compatible OpenSSL version. Therefore, RVM can be used to manage both ruby and a local install of OpenSSL.

```sh
apt install imagemagick potrace
pip install fonttools

git submodule update --init --recursive

# fontforge
(
cd ./modules/fontforge/
git checkout 4f4907d9541857b135bd0b361099e778325b4e28
git apply ../../resources/fontforge.diff
mkdir -p build
cd build
cmake -GNinja ..
ninja
ninja install
)

# woff2
(
cd ./modules/woff2/
make clean all
)

# fontcustom
rvm use 2.7
rvm pkg install openssl
rvm install 2.4 --with-openssl-dir=$HOME/.rvm/usr
gem update --system 3.3.22
(
export PATH=$PWD/modules/woff2/build:$PATH
cd ./modules/fontcustom/
git apply ../../resources/fontcustom.diff
gem build fontcustom.gemspec
gem install ./fontcustom-2.0.0.gem
)
```

# Running

```sh
cp ./resources/droid-sans-mono.ttf /tmp/base.ttf
./gen.py ./resources/instructions.json
```

The .ttf font file is copied to `~/.local/share/fonts/`, which is used by e.g. LibreOffice.

# Design

Compared to other cursed fonts, Z80 Sans has these challenges:

* **Multiple characters to render**: it would be impractical to manually define character by character all substitution rules for rendering, so we can create glyphs that combine multiple literals (e.g. mnemonics like `CALL`), however this also ties to the next point...
* **Multiple combinations**: recall that some Z80 instructions can take 16-bit addresses and registers as operands, which means that a single instruction can have up to `65536 * 7 = 458752` possible combinations;
* **Out-of-order operands**: e.g. register and offsets can be encoded into hexadecimal bytes in one order, but disassembled in another order, which complicates backtracking/lookaheads rules;
* **Little-endian addresses**: Characters for the least-significant byte need to be rendered before the most-significant byte;
* **Signed offsets**: All offsets in range `0x80..0xff` need to be rendered as a negative two's-complement number;

All of this invites a programmatic solution. While fontcustom and ImageMagick take care of generating glyphs, it seems that a convenient way to write lookup rules is the .fea format, but I didn't find a way to integrate it with fonttools' .ttx format (which is basically xml). I took the lowest common denominator approach of directly editing the .ttx of Noto Sans Mono (although glyph shapes are computed from Droid Sans Mono, as that's what I started with when patching FontForge).

A recursive descent parser is used to generate all possible glyphs, which helps with evaluating expressions in encodings (e.g. `SET b,(IX+o)` takes a bit and a displacement, encoded as expression `DD CB o C6+8*b`). These encodings were then expanded to all possible values that operands can take, before finally associating 1 or more hexadecimal bytes to each disassembly glyph required to render an expanded instruction.

There are some nice references for OpenType features, but they are written at a high-level, or in .fea(?) format:

* [OpenType Feature File Specification \| afdko](http://adobe-type-tools.github.io/afdko/OpenTypeFeatureFileSpecification.html)
* [GSUB — Glyph Substitution Table \(OpenType 1\.9\.1\) \- Typography \| Microsoft Learn](https://learn.microsoft.com/en-us/typography/opentype/spec/gsub)
* [Fonts and Layout for Global Scripts](https://simoncozens.github.io/fonts-and-layout/)
* [GitHub \- brew/opentype\-feature\-intro: An introduction to OpenType features for type designers\.](https://github.com/brew/opentype-feature-intro)
* [Features, part 3: advanced contextual alternates \| Glyphs](https://glyphsapp.com/learn/features-part-3-advanced-contextual-alternates)
* [Opentype subtitution many by many \(different number\) \- Glyphs Forum](https://forum.glyphsapp.com/t/opentype-subtitution-many-by-many-different-number/13126)

It's never very clear how to translate them to .ttx, so in the end I just converted all of the Noto Sans family and used the good ol' fashioned bruteforce approach of "learning by example". This is even more fun that it sounds, thanks to plenty of silent failures when converting from .ttx to .ttf, where lookups will not match due to some assumptions not validated by fonttools (e.g. class definitions for contextual chaining substitutions must have at least one coverage glyph with class value="1").

Pretty much most challenges were solved with contextual chaining rules. To handle addresses, each nibble in range `0..f` was encoded with distinct glyphs, with spacing characters used to create multiple substitutions, one character at a time. Displacements also have additional signed variants. This gives us a total of `(4 + 2) * 16` glyphs for numbers. This was already enough to keep the font file under the 65536 glyphs limit.

The worst part was of course out-of-order operands. However, due to the limited number of variations these have in instructions, they could be covered by the same strategy as instructions with ambiguously encoded prefixes, e.g. 
```
["SET b,(IX+o)", "DD CB o C6+8*b"],
["SET b,(IY+o)", "FD CB o C6+8*b"],
```

Is covered by the same lookup rules as:
```
["SRA (IX+o)", "DD CB o 2E"],
["SRA (IY+o)", "FD CB o 2E"],
["SRL (IX+o)", "DD CB o 3E"],
["SRL (IY+o)", "FD CB o 3E"],
```

An interesting property in the Z80 ISA is that bits and registers have up to 8 variations, and these out-of-order cases only involve offsets and one of those specific operands. Therefore, we can encode bits or registers as literals. With sufficient lookaheads, we can match up to the last hexadecimal byte, and create dedicated lookups for each case. The last literals can be reduced by generating a ligature that matches the suffix glyph. The end result was dozens more generated lookups for these cases (which can likely be grouped to reduce this number).

# Known Issues

* While all of the original instruction set should be disassembled, some instructions have minor glitches:
    * `LD (IX+o),r` is rendered as `LD (IX+o r),`;
    * `SET b,(IX+o)` is rendered as `SET b,(IX+o))`;
* "CTF quality" code 😅;

# Future Work

FontForge supports scriptable modification of features using commands [GenerateFeatureFile()](https://fontforge.org/docs/scripting/scripting-alpha.html#GenerateFeatureFile) and [MergeFeature()](https://fontforge.org/docs/scripting/scripting-alpha.html#MergeFeature) (briefly covered in [The Terrible Secret of OpenType Glyph Substitution \- Ansuz \- mskala's home page](https://ansuz.sooke.bc.ca/entry/131)). I was only aware of this after making the .ttx based implementation, but it could potentially have avoided messing with .ttx files.

For more complex instruction sets, an alternative approach that seems to have less constraints is to use font shapers. Some examples:
* [fuglede/llama\.ttf: A font for writing tiny stories](https://github.com/fuglede/llama.ttf);
* [hsfzxjy/handwriter\.ttf: Handwriting synthesis with Harfbuzz WASM\.](https://github.com/hsfzxjy/handwriter.ttf);

# Credits

* [Droid Sans Mono](https://github.com/google/fonts/tree/7503f3c66297f9ec08aecf04edf355247da70ab8/apache/droidsansmono) and [Noto Sans Mono](https://github.com/google/fonts/tree/d917462c0d0f44b2e205aeb769790a175b3e752f/ofl/notosansmono) were used as base for Z80 Sans;
* `./resources/instructions.json` was adapted from [maziac/z80\-instruction\-set](https://github.com/maziac/z80-instruction-set/blob/3b6bfaeedebd68cc590348c0231b48a4d44edfe5/src/z80InstructionSetRawData.ts);
* Inspiration for GSUB substitutions:
    * [Font with Built-In Syntax Highlighting](https://blog.glyphdrawing.club/font-with-built-in-syntax-highlighting/);
    * [Fontemon](https://www.coderelay.io/fontemon.html), in particular ["How I did it"](https://github.com/mmulet/code-relay/blob/main/markdown/HowIDidIt.md);
    * [Addition Font](https://litherum.blogspot.com/2019/03/addition-font.html);
    * [Sans Bullshit Sans](https://pixelambacht.nl/2015/sans-bullshit-sans/);

# License

* Droid Sans Mono is under [Apache Licence](./LICENSE.Apache.txt);
* Noto Sans Mono is under [Open Font License](./LICENSE.OFL.txt);
* `./resources/instructions.json` is under [GNU Lesser General Public License version 3](./LICENSE.LGPL3.txt);
* Other files are under [MIT License](./LICENSE.txt);
