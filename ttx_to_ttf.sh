#!/bin/sh

set -eux

cd ./fontcustom
rm -f fontcustom_*.ttf
last_ttx=$(find . -iname 'fontcustom_*.ttx' -print0 | xargs -r -0 ls -1 -t | head -1)
ttx "$last_ttx"

rm -f ~/.local/share/fonts/fontcustom_*.ttf
last_ttf=$(find . -iname 'fontcustom_*.ttf' -print0 | xargs -r -0 ls -1 -t | head -1)
cp "$last_ttf" ~/.local/share/fonts/
