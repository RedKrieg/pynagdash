CREATE TABLE IF NOT EXISTS `users` (
  `USER` varchar(64) NOT NULL,
  `PASSWORD` varchar(256) NOT NULL,
  `ADMIN` int(1) NOT NULL,
  `DISABLED` int(1) NOT NULL,
  PRIMARY KEY (`USER`)
);
CREATE TABLE IF NOT EXISTS `views` (
  `NAME` varchar(64) NOT NULL,
  `DESCRIPTION` varchar(512) NOT NULL,
  PRIMARY KEY (`NAME`)
)
