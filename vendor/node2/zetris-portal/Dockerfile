FROM node:22-alpine
WORKDIR /app
COPY server.js index.html simulation.js simulation.html simulation-ui.js ./
USER node
EXPOSE 3000
CMD ["node","server.js"]
