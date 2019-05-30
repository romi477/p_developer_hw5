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
* --queue, -q : очередь подключений к серверному сокету, 5
* --threads, -t : лимит потоков обработки соединений на один процесс (на один воркер), 4
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
    Time taken for tests:   11.288 seconds
    Complete requests:      50000
    Failed requests:        0
    Total transferred:      9050000 bytes
    HTML transferred:       1700000 bytes
    Requests per second:    4429.33 [#/sec] (mean)
    Time per request:       22.577 [ms] (mean)
    Time per request:       0.226 [ms] (mean, across all concurrent requests)
    Transfer rate:          782.92 [Kbytes/sec] received
    
    Connection Times (ms)
                  min  mean[+/-sd] median   max
    Connect:        0   19 150.2      0    3048
    Processing:     0    3  13.5      2     834
    Waiting:        0    3  13.5      2     834
    Total:          0   22 155.0      2    3454
    
    Percentage of the requests served within a certain time (ms)
      50%      2
      66%      2
      75%      3
      80%      3
      90%      4
      95%      5
      98%     10
      99%   1019
     100%   3454 (longest request)

    
