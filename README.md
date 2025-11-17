# from repo root
mkdir -p tools
# create files (paste contents from above)
# example using heredoc for JS Secret Finder:
cat > tools/js_secret_finder.py <<'PY'
# [PASTE THE js_secret_finder.py CONTENT HERE from above]
PY

# make executables
chmod +x tools/*.py

# add to git, commit & push
git add tools js_secret_finder.py tools/http_header_scanner.py tools/wayback_miner.py
git commit -m "Add OSINT tool stubs: JS Secret Finder, HTTP Header Scanner, Wayback Miner"
git push
