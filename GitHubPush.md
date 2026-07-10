### 1. Собираем образ
    docker build -t tnc-server:latest .
### 2. Коннектимся с github Registry
### 3. Задаем тег собранному образу
    docker tag tnc-server ghcr.io/andreufa/tnc-server:1.0
### 4. Пушим его в Registry
     docker push ghcr.io/andreufa/tnc-server:1.0


## Если изменился только образ сервера
Так как изменился только образ server, используй точечное обновление:

bash
### 1. Скачиваем новую версию образа
docker compose pull server

### 2. Пересоздаем только сервис server
docker compose up -d --no-deps --force-recreate server
Это самый чистый способ: db продолжит работать без остановки, а server получит новый образ.