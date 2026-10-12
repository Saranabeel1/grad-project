# The whole portal in one image: the built dashboard + the FastAPI backend that serves it.
# Used for hosting it online (README section 10). Running it on your own PC does not need this file.
# The folders keep the same layout as the repo, so the backend finds frontend/dist and scripts/ as usual.

# 1) build the dashboard
FROM node:20-slim AS dashboard
WORKDIR /frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

# 2) the backend, with the dashboard and the fetch scripts next to it
FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /srv/backend
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY backend/app ./app
COPY scripts /srv/scripts
COPY --from=dashboard /frontend/dist /srv/frontend/dist
# hosting services say which port to use in $PORT
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
