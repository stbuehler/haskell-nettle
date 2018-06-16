#!/bin/sh

self=$(readlink -f "$0")
base=$(dirname "${self}")

cd "${base}"

rm -rf gh-pages/*

cabal haddock --html-location='https://hackage.haskell.org/packages/archive/$pkg/latest/doc/html' --hyperlink-source --haddock-options="--hyperlinked-source --built-in-themes -q aliased --no-print-missing-docs"

cp -ar dist/doc/html/nettle/* gh-pages/
