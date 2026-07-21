Шаг 0. Подготовка: получить Personal Access Token в GitLab
Образ в реестр GitLab нельзя пушить по паролю от аккаунта — нужен Personal Access Token с правами write_registry.

Зайди в GitLab → свой профиль (аватар в правом верхнем углу) → Edit profile.
В меню слева выбери Access Tokens.
Нажми Create personal access token.
Заполни:
Name: например, docker-push.
Expiration date: поставь дату подальше (или оставь, если GitLab позволяет без даты).
Select scopes: обязательно поставь галочку напротив write_registry (иногда ещё полезно read_registry).
Нажми Create personal access token.
Скопируй токен сразу — он показывается только один раз. Назови его, например, GITLAB_TOKEN и сохрани в надёжном месте (не в git!).
Шаг 1. Локальная сборка образа
Убедись, что в корне проекта (D:\AS_Projects\TNC-server) лежат:

Dockerfile (с FROM golang:1.25-alpine и копированием migrations)
docker-compose.yml
.dockerignore (где .env и лишнее не попадают в образ)
В PowerShell:

powershell
cd D:\AS_Projects\TNC-server
docker build -t tnc-server:latest .
Проверь, что образ появился:

powershell
docker images | Select-String tnc-server
Шаг 2. Авторизация в GitLab Container Registry
Используй тот токен, который получил на шаге 0:

powershell
$username = "твой-gitlab-username"
$token = "твой-personal-access-token"

docker login registry.gitlab.com -u $username -p $token
В PowerShell пароль не будет отображаться при вводе — это нормально. Если всё ок, увидишь Login Succeeded.

$env:GITLAB_USERNAME="my-username"
$env:GITLAB_TOKEN="glpat-xxxxxxxxxxxxxxxxxxxx"
$env:GITLAB_TOKEN | docker login registry.gitlab.i-progress.tech -u $env:GITLAB_USERNAME --password-stdin


Шаг 3. Правильная разметка (tag) образа под GitLab
GitLab ожидает путь вида: registry.gitlab.com/<username>/<project>/<image>:<tag>.

Пример (подставь свои значения):

powershell
# Пример: username = alex, project = tnc-project
docker tag tnc-server:latest registry.gitlab.com/alex/tnc-project/tnc-server:latest
Если не знаешь точное имя проекта в GitLab — посмотри URL репозитория: https://gitlab.com/alex/tnc-project.git → это и есть путь.

Проверь теги:

powershell
docker images --format "{{.Repository}}:{{.Tag}}" | Select-String registry.gitlab.com
Должен увидеть свой полный путь.

Шаг 4. Отправка (push) образа в GitLab
powershell
docker push registry.gitlab.com/alex/tnc-project/tnc-server:latest
Дождись The push refers to repository [...] и Pushed для всех слоёв. После этого образ будет в GitLab Container Registry.

Проверить можно в браузере: в проекте GitLab → Build → Container Registry.

Шаг 5. Как использовать образ в docker-compose (на сервере / в CI)
Теперь в docker-compose.yml вместо build: . используй image:

yaml
services:
  db:
    image: postgres:16-alpine
    # ...

  server:
    # Вместо build: .
    image: registry.gitlab.com/alex/tnc-project/tnc-server:latest

    container_name: tnc-server
    ports:
      - "8080:8080"
      - "9000:9000"
    env_file:
      - .env
    environment:
      DATABASE_URL: "postgres://tnc:tnc@db:5432/tnc?sslmode=disable"
    depends_on:
      db:
        condition: service_healthy
    restart: unless-stopped

volumes:
  tnc-pgdata:
На сервере (или в раннере CI) достаточно сделать:

bash
docker compose pull
docker compose up -d
Никаких сборок — только скачивание готового образа.

Важные советы именно для твоего проекта
Не используй latest для продакшена. Лучше тегировать по версии или по коммиту:

powershell
git rev-parse --short HEAD
# допустим, получил abc1234
docker tag tnc-server:latest registry.gitlab.com/alex/tnc-project/tnc-server:abc1234
docker push registry.gitlab.com/alex/tnc-project/tnc-server:abc1234
Тогда в compose будет image: ...:abc1234 — легко откатываться.

Миграции внутри образа — ок. Так как ты копируешь папку migrations в образ, при каждом деплое новой версии образа сервер увидит актуальные миграции и применит их. Главное — чтобы миграции были идемпотентными (твои IF NOT EXISTS и DO $$ BEGIN IF NOT EXISTS ... — правильный подход).

Секреты не попадут в образ. Твой .env исключён через .dockerignore, а переменные передаются снаружи (env_file / environment в compose). Это безопасно.

Размер образа. С multi‑stage и Alpine образ будет компактным (обычно 20–40 МБ) — удобно для CI и быстрого деплоя.

Частые ошибки и как их быстро чинить
«denied: access denied» при push — проверь, что авторизовался (docker login) и что токен имеет write_registry, а не просто read_api.
«no basic auth credentials» — значит, docker login не прошёл или сессия истекла. Перезайди.
Образ не виден в GitLab — убедись, что путь в tag точно совпадает с путём проекта в GitLab.
Ошибка при запуске на сервере — проверь, что на сервере тоже есть .env (или секреты переданы через переменные окружения), потому что образ сам по себе их не содержит.
Бонус: минимальный .gitlab-ci.yml для твоего Go‑сервера
Если захочешь автоматизировать сборку и пуш:

yaml
stages:
  - build

build-and-push:
  stage: build
  image: docker:24
  services:
    - docker:24-dind
  variables:
    DOCKER_TLS_CERTDIR: ""
  before_script:
    - echo "$CI_REGISTRY_PASSWORD" | docker login $CI_REGISTRY -u $CI_REGISTRY_USER --password-stdin
  script:
    - docker build -t $CI_REGISTRY_IMAGE:latest .
    - docker push $CI_REGISTRY_IMAGE:latest
Здесь $CI_REGISTRY_IMAGE подставляется автоматически как registry.gitlab.com/username/project/image. В настройках проекта GitLab (CI/CD → Variables) добавь переменные CI_REGISTRY_USER и CI_REGISTRY_PASSWORD (токен с правами write_registry).



Docker Desktop группирует контейнеры не по их внутреннему имени (container_name), а по имени проекта. Чтобы не путаться 
можно явно указать имя проекта при запуске:

docker compose -f .\createdb.yml -p db-only up

Посмотреть логи контейнера // Важно исполнить эту команду в той же папке где лежит docker-compose.yml 
docker compose logs -f server 

docker compose config --services // покажет все сервисы запущенные docker-compose.yml 


## Сборка образа локально

Вариант 3A: docker save / docker load (без реестра)
Локально:

powershell
docker build -t tnc-server:local .
docker save -o tnc-server.tar tnc-server:local

### Передаёшь tnc-server.tar на сервер (scp, sftp, rclone и т.п.).
 scp -r .\tnc-server.tar tnc-prod:~/app/tnc-server
tnc-server.tar

### После этого на сервере распаковываем архив 
~/app/tnc-server$ sudo docker load -i tnc-server.tar

Проверить можно 
a.bukreev@intelligence3:~/app/tnc-server$ sudo docker images | grep tnc-server
tnc-server                                            local                 b37ff28a9031   About an hour ago   26.9MB


### Дальше в docker-compose.yml

services:
  server:
    image: tnc-server:local          # ← важно: именно этот тег
    # build: .                      # ← если есть build, лучше закомментировать для теста

### Копировать остальные файлы
scp -i $env:USERPROFILE\.ssh\id_ed25519_tnc .\docker-compose.yml .\.env tnc-prod:/home/a.bukreev/app/tnc-server/

