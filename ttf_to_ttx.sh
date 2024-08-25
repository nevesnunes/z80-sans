#!/bin/sh

set -eux

rm -f .fontcustom-manifest.json
env GEM_PATH="$HOME/.gem/ruby/2.7.0:$GEM_PATH" ~/.gem/ruby/2.7.0/gems/fontcustom-2.0.0/bin/fontcustom compile ./out_svg/ --debug

cd ./fontcustom
rm -f fontcustom_*.ttx
last_ttf=$(find . -iname 'fontcustom_*.ttf' -print0 | xargs -r -0 ls -1 -t | head -1)
ttx "$last_ttf"
