DELETE FROM tenant WHERE id > 100;
DELETE FROM visit_history WHERE created_at >= '1654041600';
UPDATE id_generator SET id=2678400000 WHERE stub='a';
ALTER TABLE id_generator AUTO_INCREMENT=2678400000;

DROP TABLE IF EXISTS `latest_player_score`;
CREATE TABLE `latest_player_score` (
    `tenant_id` BIGINT NOT NULL,
    `player_id` VARCHAR(255) NOT NULL,
    `competition_id` VARCHAR(255) NOT NULL,
    score BIGINT NOT NULL,
    row_num BIGINT NOT NULL,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    PRIMARY KEY (`tenant_id`, `competition_id`, `player_id`)
) ENGINE=InnoDB DEFAULT CHARACTER SET=utf8mb4;

/*
事前に作っておく。初期データ時点の最新スコア
LOAD DATA INFILE '/var/lib/mysql-files/latest_scores.csv' INTO TABLE player_score FIELDS TERMINATED BY ',' (id, tenant_id, player_id, competition_id, score, row_num, created_at, updated_at);

DROP TABLE IF EXISTS player_score;
CREATE TABLE player_score (
    id VARCHAR(255) NOT NULL PRIMARY KEY,
    tenant_id BIGINT NOT NULL,
    player_id VARCHAR(255) NOT NULL,
    competition_id VARCHAR(255) NOT NULL,
    score BIGINT NOT NULL,
    row_num BIGINT NOT NULL,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL
) ENGINE=InnoDB DEFAULT CHARACTER SET=utf8mb4;
LOAD DATA LOCAL
    INFILE '/home/isucon/webapp/tenant_db/latest_scores.csv'
INTO TABLE
    player_score
FIELDS TERMINATED BY ','
;
*/

INSERT INTO latest_player_score (tenant_id, player_id, competition_id, score, row_num, created_at, updated_at)
SELECT
    tenant_id, player_id, competition_id, score, row_num, created_at, updated_at
FROM player_score;

DROP INDEX IF EXISTS `visit_history_idx`;
CREATE INDEX IF NOT EXISTS `visit_history_ids` ON `visit_history` (`tenant_id`, `competition_id`, `player_id`, `created_at`);
