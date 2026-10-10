FROM node:24-alpine as build

WORKDIR /app

COPY package*.json ./
RUN npm install

COPY . .

# Set API URL to empty (paths already include /api prefix, nginx proxies to backend)
ENV VITE_API_URL=
RUN npm run build

FROM nginx:alpine
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
