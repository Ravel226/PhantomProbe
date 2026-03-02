# PhantomProbe Agent Configuration

## Project Overview
PhantomProbe is a reconnaissance scanner for penetration testing.
- Language: Python 3.8+
- Repository: https://github.com/Ravel226/PhantomProbe
- Current Version: 0.5.0

## Agent Capabilities

### Coder Agent
- Implement new reconnaissance modules
- Fix bugs in phantomprobe.py
- Add new CLI flags and options

### Researcher Agent
- Find CVE patterns and signatures
- Research new reconnaissance techniques
- Analyze security headers and their implications

### Tester Agent
- Run scans against test targets
- Verify screenshot capture works
- Test CVE matching accuracy

## Common Tasks

### Add new reconnaissance module
1. Create new method in ReconEngine or ActiveReconEngine
2. Return List[Finding] with proper severity
3. Call from run() method
4. Update README with new feature

### Add CLI flag
1. Add to argument parsing in main()
2. Create flag variable (e.g., --newflag)
3. Implement feature logic
4. Update help text

### Test features
```bash
python3 phantomprobe.py laurellewourougou.com --phase2 --cve --screenshot
```

### Commit and push
```bash
git add -A
git commit -m "message"
git push
```

## Code Style
- Standard library preferred
- Type hints required
- Docstrings for all classes and methods
- Severity enum for findings
