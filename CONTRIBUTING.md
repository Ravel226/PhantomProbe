# Contributing to PhantomProbe

Thank you for your interest in contributing to PhantomProbe! This document provides guidelines for contributing.

## Development Setup

```bash
# Clone the repository
git clone https://github.com/Ravel226/PhantomProbe.git
cd PhantomProbe

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install in development mode
pip install -e ".[all]"

# Install development dependencies
pip install pytest pytest-cov black flake8 isort
```

## Running Tests

```bash
# Run all tests
pytest tests/

# Run with coverage
pytest tests/ --cov=phantomprobe --cov-report=html

# Run specific test file
pytest tests/test_dashboard.py -v
```

## Code Style

We use:
- **Black** for code formatting
- **flake8** for linting
- **isort** for import sorting

```bash
# Format code
black src/ tests/

# Sort imports
isort src/ tests/

# Check linting
flake8 src/ tests/
```

## Pull Request Process

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests and ensure they pass
5. Update documentation if needed
6. Commit your changes (`git commit -m 'Add amazing feature'`)
7. Push to the branch (`git push origin feature/amazing-feature`)
8. Open a Pull Request

## Commit Message Guidelines

- Use present tense ("Add feature" not "Added feature")
- Use imperative mood ("Move cursor to..." not "Moves cursor to...")
- Limit the first line to 72 characters or less
- Reference issues and pull requests liberally after the first line

## Testing Guidelines

- Write tests for new features
- Ensure tests pass before submitting PR
- Aim for >80% code coverage
- Test both success and failure cases

## Security

- Never commit secrets or credentials
- Report security vulnerabilities privately
- Follow secure coding practices

## Questions?

Feel free to open an issue or reach out to the maintainers.
