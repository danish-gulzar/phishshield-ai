.PHONY: install playground run test clean

install:
	uv sync

playground:
	uv run adk web app --host 127.0.0.1 --port 18081 --reload_agents

run:
	uv run uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

test:
	uv run pytest tests/

clean:
	rm -rf .adk/ __pycache__/ *.pyc .pytest_cache/ .ruff_cache/
