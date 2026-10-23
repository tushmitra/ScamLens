# Build the static site, then serve it with nginx.
# The API URL is baked in at build time (Vite env vars are public; never put secrets here).
FROM node:22-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm install --no-audit --no-fund
COPY . .
ARG VITE_SCAMLENS_API_URL=http://localhost:8000
ENV VITE_SCAMLENS_API_URL=$VITE_SCAMLENS_API_URL
RUN npm run build

FROM nginx:1.27-alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
