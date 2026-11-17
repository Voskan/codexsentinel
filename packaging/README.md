# Distribution channels

Maintainer notes for the Homebrew tap and the VS Code extension. Both are
built from the release binaries that `.github/workflows/release.yml` builds
with the SLSA Go builder and lists in `checksums.txt`.

## Homebrew

`homebrew/codexsentinel.rb` is the formula template. `scripts/homebrew-formula.sh`
fills in the version and the SHA-256 sums of the darwin and linux binaries
(amd64 and arm64) from a release's `checksums.txt`:

```bash
sh scripts/homebrew-formula.sh v2.0.0 checksums.txt > codexsentinel.rb
```

The `homebrew` job of the release workflow runs the script for every published
release that is not marked as a pre-release and commits the result to
`Formula/codexsentinel.rb` in the tap repository.

One-time setup:

1. Create the public repository `Voskan/homebrew-tap` with an initial commit
   (for example a README), so the workflow has a default branch to check out.
   Homebrew maps `brew install Voskan/tap/codexsentinel` to this repository.
2. Create a fine-grained personal access token with access to that repository
   only and the permission **Contents: read and write**.
3. Add the token to `Voskan/codexsentinel` as the Actions secret
   `HOMEBREW_TAP_TOKEN`. Without it the job is skipped with a warning.

To publish the formula for a release that was made before the setup, download
its `checksums.txt`, render the formula with the script and commit it to the
tap as `Formula/codexsentinel.rb`. Check it with:

```bash
brew install --build-from-source Voskan/tap/codexsentinel
```

```bash
brew test codexsentinel
```

```bash
brew audit --strict --online Voskan/tap/codexsentinel
```

## VS Code

The extension lives in `editors/vscode`. Its `version` in `package.json`
should follow the CLI release it is tested with.

One-time setup:

1. Create a publisher in the
   [Visual Studio Marketplace management page](https://marketplace.visualstudio.com/manage).
   Its ID must match `publisher` in `editors/vscode/package.json` (`Voskan`).
2. Create an Azure DevOps personal access token with the
   **Marketplace: Manage** scope and the organization set to
   **All accessible organizations**.
3. Optionally, publish to Open VSX for VSCodium and other editors: sign in at
   [open-vsx.org](https://open-vsx.org), create the `Voskan` namespace and an
   access token.

Publishing a version:

```bash
cd editors/vscode && npm install && npx @vscode/vsce package
```

```bash
npx @vscode/vsce publish --packagePath codexsentinel-2.0.0.vsix
```

```bash
npx ovsx publish codexsentinel-2.0.0.vsix --pat "$OVSX_TOKEN"
```

`vsce publish` asks for the Marketplace token, or reads it from `VSCE_PAT`.
