# Contributing to IndiFinder

We follow a structured branching and commit workflow to keep development organized.

## Branching Strategy

When working on new changes, always create a **new branch** from the main development branch (`main` or `develop`). Do not commit directly to `main`.

### Branch Naming Convention

Use the following prefixes for your branch names:

- **`feat/`** : For new features or significant additions.  
  *Example:* `feat/add-triage-integration`, `feat/user-login-system`
- **`fix/`** : For bug fixes or error corrections.  
  *Example:* `fix/api-timeout-issue`, `fix/typo-in-readme`
- **`docs/`** : For documentation updates only.  
  *Example:* `docs/update-installation-guide`
- **`refactor/`** : For code restructuring without changing behavior.  
  *Example:* `refactor/simplify-downloader-logic`
- **`test/`** : For adding or correcting tests.  
  *Example:* `test/add-unit-tests-for-api`
- **`chore/`** : For maintenance tasks, build scripts, or dependency updates.  
  *Example:* `chore/update-requirements`, `chore/bump-version`

### Workflow Steps

1.  **Pull Latest Changes**: Ensure your local main branch is up to date.
    ```bash
    git checkout main
    git pull origin main
    ```
2.  **Create a New Branch**: Use a descriptive name with the correct prefix.
    ```bash
    git checkout -b feat/my-new-feature
    ```
3.  **Make Changes & Commit**: Write clear commit messages.
    ```bash
    git add .
    git commit -m "feat: implement basic triage api client"
    ```
4.  **Push & Pull Request**: Push your branch and open a PR on GitHub.
    ```bash
    git push origin feat/my-new-feature
    ```

## Commit Messages

We encourage using Conventional Commits for clarity:

- `feat: allow users to configure timeouts`
- `fix: resolve crash when api key is missing`
- `docs: update contributing guidelines`
