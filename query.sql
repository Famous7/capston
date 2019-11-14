CREATE DATABASE capston;

USE capston;

CREATE TABLE radio_info_tbl(id int NOT NULL AUTO_INCREMENT PRIMARY KEY,
create_time datetime NOT NULL,
wi_fi JSON NOT NULL,
ble JSON NOT NULL,
num_of_visitors int NOT NULL
) ENGINE = INNODB DEFAULT CHARSET=utf8;