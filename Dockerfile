# Используем официальный образ Node.js версии 22
FROM node:22-alpine

# Устанавливаем рабочую директорию внутри контейнера
WORKDIR /app

# Копируем package.json и package-lock.json (если есть)
COPY package*.json ./

# Устанавливаем зависимости
RUN npm install

# Копируем остальные файлы проекта
COPY . .

# Команда для запуска скрипта раз в день
CMD while true; do \
      npm start; \
      sleep 86400; \
    done