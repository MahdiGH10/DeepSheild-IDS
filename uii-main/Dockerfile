FROM node:20-alpine AS deps
WORKDIR /app
COPY uii-main/package.json uii-main/package-lock.json ./
RUN npm ci

FROM node:20-alpine AS builder
WORKDIR /app
ARG VITE_API_BASE
ARG VITE_ANALYST_API_KEY
ENV VITE_API_BASE=${VITE_API_BASE}
ENV VITE_ANALYST_API_KEY=${VITE_ANALYST_API_KEY}
COPY --from=deps /app/node_modules ./node_modules
COPY uii-main ./
RUN npm run build

FROM nginx:1.27-alpine AS runner
ENV PORT=8080
COPY --from=builder /app/dist /usr/share/nginx/html
COPY uii-main/nginx.conf.template /etc/nginx/templates/default.conf.template
EXPOSE 8080
