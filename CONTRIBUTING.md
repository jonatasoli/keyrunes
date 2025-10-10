# Contributing to KeyRunes

First off, thank you for considering contributing to KeyRunes! Whether it's code, documentation, bug reports, or feature requests, your help makes KeyRunes better for everyone. This guide will help you get started and make the process smooth for you and the maintainers.

---

## Table of Contents

1. [How to Contribute](#how-to-contribute)
2. [Reporting Bugs](#reporting-bugs)
3. [Requesting Features](#requesting-features)
4. [Development Setup](#development-setup)
5. [Code Style and Standards](#code-style-and-standards)
6. [Submitting Pull Requests](#submitting-pull-requests)
7. [Community Guidelines](#community-guidelines)
8. [Acknowledgements](#acknowledgements)

---

## How to Contribute

There are many ways you can contribute:

- **Code Contributions**: Fix bugs, implement new features, or improve existing code.
- **Documentation**: Improve README, write guides, or clarify examples.
- **Testing**: Add or improve unit, integration, or end-to-end tests.
- **Feedback**: Report issues, suggest features, or provide performance insights.

Before contributing code, please check the existing issues to avoid duplication.

---

## Reporting Bugs

If you find a bug, please submit an issue with:

- A clear and descriptive title.
- Steps to reproduce the problem.
- Expected vs actual behavior.
- Relevant environment information (OS, Rust version, DB, etc.).
- Logs or screenshots, if applicable.

This helps maintainers reproduce and fix the issue faster.

---

## Requesting Features

Feature requests should include:

- A clear description of the feature.
- Why it is needed and how it improves KeyRunes.
- Optional examples or mockups.

Feature requests are discussed openly and may be implemented collaboratively.

---

## Development Setup

Follow these steps to get KeyRunes running locally:

1. **Clone the repository:**
```bash
   git clone https://github.com/jonatasoli/keyrunes.git && cd keyrunes
```

Start the database and services using Docker Compose:

Create a file named `.env` This allows docker compose to pick up env vars instead of manually passing them in the cli command everytime.
Setup your env variables with values using .env-example` file listed in the main directory as an example.

Run the below to create db tables / migrations
```bash
   sqlx migrate run 
```

Run the below
```bash
   docker-compose up
```

Run the web application:

```bash
   cargo run --bin keyrunes
```

Run the CLI application:
```bash
   cargo run --bin cli
```

Run tests:
```bash
  cargo test 
```

Code Style and Standards

Follow Rust community conventions.

Use meaningful variable and function names.

Write tests for new features and bug fixes.

Keep code modular and well-documented.

Use Clippy to catch warnings:

```bash
  cargo clippy
```

Submitting Pull Requests
Fork the repository.

Create a new branch for your feature/bugfix.

Write code and tests according to the guidelines.

Ensure all tests pass.

Submit a pull request with a clear description of the changes.

Pull requests are reviewed collaboratively. Be prepared to make changes based on feedback.

Community Guidelines

- We value respectful and constructive communication. Please follow:

- Be respectful to all contributors.

- Provide clear and concise feedback.

- Stay on-topic and avoid off-topic discussions in issues/PRs.

- Follow the [Code of Conduct](CODE_OF_CONDUCT.md)