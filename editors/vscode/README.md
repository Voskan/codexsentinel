# CodexSentinel for VS Code

Shows [CodexSentinel](https://github.com/Voskan/codexsentinel) findings for Go
files as diagnostics. The extension starts `codex-cli lsp`, the language
server built into the CodexSentinel CLI, and talks to it over stdio.

- Findings appear when a Go file is opened or saved, with CWE, OWASP and the
  data flow in the hover text.
- Quick fixes apply a finding's fix or add a
  `//codex:ignore <rule> -- TODO: document reason` comment. The suppression is
  not offered when the configuration sets
  `suppression.forbid_new_suppressions`.
- The configuration (`.codexsentinel.yaml` and friends) is read from the
  workspace root, as for `codex-cli scan`.

The extension runs next to the Go extension and gopls; it does not replace
them.

## Requirements

`codex-cli` 2.0 or newer, either on your `PATH` or configured with
`codexsentinel.path`. Install it with Homebrew, the install script or
`go install`, as described in the
[installation guide](https://github.com/Voskan/codexsentinel#installation):

```bash
brew install Voskan/tap/codexsentinel
```

## Settings

| Setting | Default | Description |
| --- | --- | --- |
| `codexsentinel.path` | `codex-cli` | Path to the binary. A bare name is looked up on `PATH`; `~` and `${workspaceFolder}` are expanded, and a relative path is resolved against the first workspace folder. |
| `codexsentinel.args` | `[]` | Extra arguments for `codex-cli lsp`, e.g. `["--debounce", "500ms"]` or `["--log-file", "/tmp/codexsentinel-lsp.log"]`. |
| `codexsentinel.trace.server` | `off` | `messages` or `verbose` traces the protocol in the CodexSentinel output channel. |

Changing `codexsentinel.path` or `codexsentinel.args` restarts the server.

## Commands

- **CodexSentinel: Restart Language Server**
- **CodexSentinel: Show Output**

## Building from source

```bash
cd editors/vscode
npm install
npm run compile
```

Open the folder in VS Code and press F5 to start an Extension Development
Host. To build a `.vsix` package and install it locally:

```bash
npx @vscode/vsce package
```

```bash
code --install-extension codexsentinel-2.0.0.vsix
```

## License

MIT
