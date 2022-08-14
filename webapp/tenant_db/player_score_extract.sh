#!/bin/bash

rm -rf latest_scores.csv

for f in $(ls *.db | grep -v -e '^1.db' | sort); do
	echo "processing $f"
	sqlite3 -csv "$f" "
SELECT * FROM player_score ps
WHERE (tenant_id, competition_id, player_id, row_num) = (
	SELECT tenant_id, competition_id, player_id, MAX(row_num) OVER (PARTITION BY competition_id, player_id)
	FROM player_score pss
	WHERE ps.tenant_id = pss.tenant_id
	AND ps.competition_id = pss.competition_id
	AND ps.player_id = pss.player_id
	GROUP BY tenant_id, competition_id, player_id
);
" >> latest_scores.csv
done

echo "done"
