## OTUServer
Простой синхронный prefork-http сервер. Реализация GET, HEAD методов.
При запуске мастер-сервера создаются потомки в виде новых процессов. Потомок, получивший клиентское соединение,
создайт новый поток.


#### Запуск сервера:
    $ python http.py [*args]

#### Аргументы командной строки (значение по умолчанию):

* --master, -m :  хост сервера, http://127.0.0.1
* --port, -p :  порт сервера, 8888
* --root, -r :  корневая директория для доступа к файлам, ./rootdir
* --workers, -w :  колическтво воркеров (потомков мастер-сервера), 5
* --queue, -q : очередь подключений к серверному сокету, 4
* --threads, -t : лимит потоков обработки соединений на один процесс (на один воркер), 20
* --log, -l :  уровень логирования, INFO

#### Запуск базовых тестов:
    $ python -m unittest httptest.HttpServer

#### Результаты нагрузочного тестирования:

    ab -n 50000 -c 100 -r "http://localhost:8888/httptest/dir2/"
    
    This is ApacheBench, Version 2.3 <$Revision: 1807734 $>
    Copyright 1996 Adam Twiss, Zeus Technology Ltd, http://www.zeustech.net/
    Licensed to The Apache Software Foundation, http://www.apache.org/
    
    Benchmarking localhost (be patient)
    Completed 5000 requests
    Completed 10000 requests
    Completed 15000 requests
    Completed 20000 requests
    Completed 25000 requests
    Completed 30000 requests
    Completed 35000 requests
    Completed 40000 requests
    Completed 45000 requests
    Completed 50000 requests
    Finished 50000 requests
    
    
    Server Software:        Simple
    Server Hostname:        localhost
    Server Port:            8888
    
    Document Path:          /httptest/dir2/
    Document Length:        34 bytes
    
    Concurrency Level:      100
    Time taken for tests:   11.695 seconds
    Complete requests:      50000
    Failed requests:        0
    Total transferred:      9050000 bytes
    HTML transferred:       1700000 bytes
    Requests per second:    4275.34 [#/sec] (mean)
    Time per request:       23.390 [ms] (mean)
    Time per request:       0.234 [ms] (mean, across all concurrent requests)
    Transfer rate:          755.70 [Kbytes/sec] received
    
    Connection Times (ms)
                  min  mean[+/-sd] median   max
    Connect:        0   19 151.9      0    3050
    Processing:     0    4  15.3      3     837
    Waiting:        0    4  15.3      2     837
    Total:          0   22 157.3      3    3436
    
    Percentage of the requests served within a certain time (ms)
      50%      3
      66%      4
      75%      4
      80%      5
      90%      6
      95%      7
      98%     11
      99%   1020
     100%   3436 (longest request)
    
