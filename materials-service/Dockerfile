FROM node:20-alpine
WORKDIR /app
COPY package.json ./
RUN npm i --omit=dev
COPY index.mjs ./
EXPOSE 3004
CMD ["node","index.mjs"]
