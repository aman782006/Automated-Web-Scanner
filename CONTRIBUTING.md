# Contributing to Automated Web Security Scanner

Thank you for considering contributing to the Automated Web Security Scanner! Contributions from the community help make this project more useful and secure.

---

## Code of Conduct

- Be welcoming, respectful, and constructive.
- Maintain focus on defensive security, safety guardrails, and educational value.
- Never submit active exploitation modules, offensive payloads, or destructive scanning features.

---

## How to Contribute

### 1. Reporting Bugs
- Check the [Issues](../../issues) tab to verify the issue has not already been reported.
- If not, open a new issue using the **Bug Report** template.
- Include Python version, OS, reproduction steps, expected vs. observed behavior, and terminal output.

### 2. Suggesting Enhancements
- Open an issue using the **Feature Request** template.
- Clearly describe the proposed feature, the rationale, and relevant RFCs or security standards (e.g., OWASP, MDN web docs).

### 3. Pull Requests

1. **Fork the repository** and clone your fork:
   ```bash
   git clone https://github.com/<your-username>/automated-web-scanner.git
   cd automated-web-scanner
   ```

2. **Create a virtual environment & install dependencies**:
   ```bash
   # Windows
   python -m venv venv
   venv\Scripts\activate

   # Linux / macOS
   python3 -m venv venv
   source venv/bin/activate

   pip install -r requirements.txt
   ```

3. **Create a feature branch**:
   ```bash
   git checkout -b feature/your-feature-name
   ```

4. **Write tests & verify existing tests pass**:
   ```bash
   pytest tests/ -v
   ```
   > All 160+ unit tests must pass before submitting your PR. Please add unit tests for any new rules or logic.

5. **Commit your changes**:
   ```bash
   git commit -m "feat(headers): add detection for Cross-Origin-Embedder-Policy"
   ```

6. **Push and open a Pull Request**:
   - Push to your fork: `git push origin feature/your-feature-name`
   - Open a PR against the `main` branch with a clear description of the change.

---

## Design Principles

- **Safe & Non-Intrusive**: Only perform non-destructive, read-only HTTP header queries.
- **SSRF Protection**: Any new request logic MUST pass through `scanner.validator.validate_target` or respect the blocked IP ranges.
- **In-Memory Simplicity**: Maintain zero-database, self-contained architecture.
- **Comprehensive Unit Testing**: Every rule and parser must have mocked unit test coverage.
