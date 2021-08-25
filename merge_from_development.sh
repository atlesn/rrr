#!/bin/sh

git merge -s recursive --no-commit --no-ff development || exit 1
rm -f .development
git commit -a -m "Merge in changes from development branch"

