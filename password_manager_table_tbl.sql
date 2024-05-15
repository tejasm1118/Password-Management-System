CREATE TABLE `password_manager_table` (
  `UserID` int NOT NULL AUTO_INCREMENT,
  `UserName` varchar(45) NOT NULL,
  `Password` varchar(120) NOT NULL,
  PRIMARY KEY (`UserID`),
  UNIQUE KEY `Sl No_UNIQUE` (`UserID`)
) ENGINE=InnoDB AUTO_INCREMENT=151 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
