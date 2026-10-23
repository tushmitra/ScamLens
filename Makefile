.PHONY: install test test-backend test-frontend run-backend run-frontend manifest docker

install:
	cd backend && pip install -r requirements-dev.txt
	cd frontend && npm install

test: test-backend test-frontend

test-backend:
	cd backend && python -m pytest

test-frontend:
	cd frontend && npm test && npm run build

run-backend:
	cd backend && uvicorn app.main:app --reload --port 8000

run-frontend:
	cd frontend && cp -n .env.example .env; npm run dev

manifest:
	cd backend && python scripts/model_manifest.py

docker:
	docker compose up --build
