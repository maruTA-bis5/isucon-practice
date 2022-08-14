#!/bin/bash

rm -rf competitions.csv

for f in $(ls *.db | sort); do
	echo "processing $f"
	sqlite3 -csv "$f" "
SELECT * FROM competition
" >> competitions.csv
done

echo "done"
