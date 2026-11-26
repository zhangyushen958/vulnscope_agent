.PHONY: serve test kb
serve:
	bash scripts/start.sh
test:
	python -m pytest tests/ -q
kb:
	@test -n "$(HISTORY)" || (echo 'Usage: make kb HISTORY=/path/to/course_history.jsonl'; exit 1)
	python -m scripts.build_kb $(HISTORY)
