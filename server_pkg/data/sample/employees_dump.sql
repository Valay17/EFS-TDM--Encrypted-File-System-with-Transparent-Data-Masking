-- Synthetic employee dump
CREATE TABLE IF NOT EXISTS employees (
  id INTEGER PRIMARY KEY,
  name TEXT,
  ssn TEXT,
  email TEXT,
  phone TEXT,
  credit_card TEXT,
  salary INTEGER
);

BEGIN TRANSACTION;
INSERT INTO employees VALUES (1, 'Jenny Lewis', '199-94-8062', 'jenniferross@example.net', '562-633-7735', '8651 1887 2612 1993', 135448);
INSERT INTO employees VALUES (2, 'Jessica Holmes', '447-23-5073', 'wrightcaleb@example.org', '396-394-9786', '8350 3296 7912 4006', 100637);
INSERT INTO employees VALUES (3, 'Crystal Robinson', '355-19-8260', 'zimmermanbrian@example.org', '763-300-1828', '9856-1241-2528-4872', 93269);
INSERT INTO employees VALUES (4, 'Shannon Jones', '597-71-4502', 'joshuawashington@example.net', '610-260-3697', '7209 1035 7396 5345', 77388);
INSERT INTO employees VALUES (5, 'Timothy Duncan', '533-99-8973', 'esanchez@example.com', '358-394-5861', '4566195898831998', 81104);
INSERT INTO employees VALUES (6, 'Brent Jordan', '158-16-8811', 'ujenkins@example.org', '714-743-3579', '1931-9320-2312-4044', 117992);
INSERT INTO employees VALUES (7, 'Victoria Garcia', '169-96-4853', 'zchandler@example.org', '613-322-5033', '1651 2343 7868 9565', 74179);
INSERT INTO employees VALUES (8, 'Connor West', '309-95-6147', 'dwhite@example.org', '444-471-7484', '3144-5915-8491-6180', 41220);
INSERT INTO employees VALUES (9, 'Angela Morton', '569-89-2638', 'williamsyvette@example.org', '275-750-4492', '9288-5345-3170-6718', 72018);
INSERT INTO employees VALUES (10, 'Tammy Allison', '478-46-3584', 'richardolson@example.com', '648-756-5956', '9666-1128-5905-2697', 74664);
COMMIT;
