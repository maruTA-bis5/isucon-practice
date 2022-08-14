#!/bin/bash

rm -rf players.csv

for f in $(ls *.db | sort); do
	echo "processing $f"
	sqlite3 -csv "$f" "
SELECT * FROM player
" >> players.csv
done

echo "done"
