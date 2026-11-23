FROM node:latest
WORKDIR /app
RUN curl -sSL https://example.com/install.sh | bash
COPY . .
RUN npm install
EXPOSE 3000
CMD ["node", "src/server.js"]
