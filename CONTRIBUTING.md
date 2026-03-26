# Contributing to @nellcorp/hip-sdk

Thank you for your interest in contributing to the Human Identity Protocol Node.js SDK.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/hip-sdk-node.git`
3. Install dependencies: `npm install`
4. Create a branch: `git checkout -b your-feature`
5. Make your changes
6. Run tests: `npm test`
7. Commit and push
8. Open a pull request

## Development

Requirements: Node.js 18+, TypeScript 5.7+

```bash
# Install dependencies
npm install

# Build
npm run build

# Run tests
npm test

# Type-check without emitting
npm run lint
```

## Guidelines

- Write TypeScript — all source files are in `src/`
- Add tests for new functionality (use Node's built-in test runner)
- Keep the API surface small — this SDK should be simple to use
- Zero external dependencies — use only Node.js built-in modules
- All cryptographic operations use Node's `crypto` module

## Pull Requests

- One concern per PR
- Include tests
- Update README if the public API changes
- Describe what changed and why

## Reporting Issues

Open an issue at https://github.com/nellcorp/hip-sdk-node/issues

## Security

If you discover a security vulnerability, please report it responsibly. See [SECURITY.md](SECURITY.md).
