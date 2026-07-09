### 1. Собираем образ
    docker build -t tnc-server:latest .
### 2. Коннектимся с github Registry
### 3. Задаем тег собранному образу
    docker tag tnc-server ghcr.io/andreufa/tnc-server:1.0
### 4. Пушим его в Registry
     docker push ghcr.io/andreufa/tnc-server:1.0