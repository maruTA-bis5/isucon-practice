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

DROP TABLE IF EXISTS `competition_billing`;
CREATE TABLE `competition_billing` (
    tenant_id BIGINT NOT NULL,
    competition_id VARCHAR(255) NOT NULL,
    title TEXT NOT NULL,
    player_count BIGINT NOT NULL,
    visitor_count BIGINT NOT NULL,
    billing_player_yen BIGINT GENERATED ALWAYS AS (100 * player_count) STORED,
    billing_visitor_yen BIGINT GENERATED ALWAYS AS (10 * visitor_count) STORED,
    billing_yen BIGINT GENERATED ALWAYS AS (billing_player_yen + billing_visitor_yen) STORED,
    PRIMARY KEY (tenant_id, competition_id)
) ENGINE=InnoDB DEFAULT CHARACTER SET=utf8mb4;

DROP TABLE IF EXISTS `player`;
CREATE TABLE `player` (
  id VARCHAR(255) NOT NULL PRIMARY KEY,
  tenant_id BIGINT NOT NULL,
  display_name TEXT NOT NULL,
  is_disqualified BOOLEAN NOT NULL,
  created_at BIGINT NOT NULL,
  updated_at BIGINT NOT NULL,
  INDEX (tenant_id)
) ENGINE=InnoDB DEFAULT CHARACTER SET=utf8mb4;

INSERT INTO `player`(id, tenant_id, display_name, is_disqualified, created_at, updated_at)
SELECT * FROM initial_player;
-- LOAD DATA INFILE '/var/lib/mysql-files/players.csv' INTO TABLE initial_player FIELDS TERMINATED BY ',' (id, tenant_id, display_name, is_disqualified, created_at, updated_at);

