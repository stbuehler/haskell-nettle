#!/bin/sh

self=$(readlink -f "$0")
base=$(dirname "${self}")

cd "${base}"

rm -rf gh-pages/*

cabal haddock --html-location='http://hackage.haskell.org/packages/archive/$pkg/latest/doc/html' --hyperlink-source --haddock-options="--built-in-themes -q aliased"

cp -ar dist/doc/html/nettle/* gh-pages/
