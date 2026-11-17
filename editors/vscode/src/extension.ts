import * as os from 'os';
import * as path from 'path';
import * as vscode from 'vscode';
import {
  LanguageClient,
  LanguageClientOptions,
  ServerOptions,
} from 'vscode-languageclient/node';

const SECTION = 'codexsentinel';

let client: LanguageClient | undefined;
let output: vscode.OutputChannel | undefined;

export async function activate(context: vscode.ExtensionContext): Promise<void> {
  output = vscode.window.createOutputChannel('CodexSentinel');
  context.subscriptions.push(output);

  context.subscriptions.push(
    vscode.commands.registerCommand(`${SECTION}.restartServer`, () => restart()),
    vscode.commands.registerCommand(`${SECTION}.showOutput`, () => output?.show(true)),
    vscode.workspace.onDidChangeConfiguration((event) => {
      if (
        event.affectsConfiguration(`${SECTION}.path`) ||
        event.affectsConfiguration(`${SECTION}.args`)
      ) {
        void restart();
      }
    }),
  );

  await start();
}

export async function deactivate(): Promise<void> {
  await stop();
}

async function start(): Promise<void> {
  const config = vscode.workspace.getConfiguration(SECTION);
  const command = resolveCommand(config.get<string>('path', 'codex-cli'));
  const args = ['lsp', ...config.get<string[]>('args', [])];
  const cwd = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;

  // The server speaks JSON-RPC on stdin/stdout. No transport is set on
  // purpose: with one the client would append a --stdio flag that
  // `codex-cli lsp` does not accept.
  const serverOptions: ServerOptions = {
    run: { command, args, options: { cwd } },
    debug: { command, args, options: { cwd } },
  };

  const clientOptions: LanguageClientOptions = {
    documentSelector: [{ scheme: 'file', language: 'go' }],
    outputChannel: output,
    traceOutputChannel: output,
  };

  client = new LanguageClient(SECTION, 'CodexSentinel', serverOptions, clientOptions);
  try {
    await client.start();
  } catch (err) {
    client = undefined;
    const message = err instanceof Error ? err.message : String(err);
    output?.appendLine(`Could not start "${command} lsp": ${message}`);
    const choice = await vscode.window.showErrorMessage(
      `CodexSentinel: could not start "${command} lsp". Install codex-cli or set codexsentinel.path.`,
      'Open Settings',
      'Installation Guide',
    );
    if (choice === 'Open Settings') {
      await vscode.commands.executeCommand('workbench.action.openSettings', `${SECTION}.path`);
    } else if (choice === 'Installation Guide') {
      await vscode.env.openExternal(
        vscode.Uri.parse('https://github.com/Voskan/codexsentinel#installation'),
      );
    }
  }
}

async function stop(): Promise<void> {
  const running = client;
  client = undefined;
  if (running) {
    await running.stop();
  }
}

async function restart(): Promise<void> {
  await stop();
  await start();
}

// resolveCommand expands ~ and ${workspaceFolder} and resolves relative paths
// against the first workspace folder. A bare name is left for PATH lookup.
function resolveCommand(configured: string): string {
  let value = configured.trim() || 'codex-cli';
  const folder = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
  if (folder) {
    value = value.replace(/\$\{workspaceFolder\}/g, () => folder);
  }
  if (value === '~' || value.startsWith('~/') || value.startsWith('~\\')) {
    value = path.join(os.homedir(), value.slice(1));
  }
  const hasSeparator = value.includes('/') || value.includes('\\');
  if (hasSeparator && !path.isAbsolute(value) && folder) {
    value = path.resolve(folder, value);
  }
  return value;
}
