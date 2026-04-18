FROM node:22-slim
WORKDIR /app
COPY package.json ./
COPY src/ src/
CMD ["node", "--test", "src/*.test.js"]
