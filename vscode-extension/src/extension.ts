import * as vscode from "vscode";
import { execFile } from "child_process";

function getPort(folderPath: string): Promise<string> {
  return new Promise((resolve, reject) => {
    execFile("phx-port", [], { cwd: folderPath }, (error, stdout, stderr) => {
      if (error) {
        reject(new Error(stderr.trim() || error.message));
        return;
      }
      const port = stdout.trim();
      if (!/^\d+$/.test(port)) {
        reject(new Error(`Unexpected output from phx-port: ${port}`));
        return;
      }
      resolve(port);
    });
  });
}

function resolveFolder(uri?: vscode.Uri): string | undefined {
  if (uri) {
    return uri.fsPath;
  }
  const workspaceFolders = vscode.workspace.workspaceFolders;
  if (workspaceFolders && workspaceFolders.length === 1) {
    return workspaceFolders[0].uri.fsPath;
  }
  return undefined;
}

export function activate(context: vscode.ExtensionContext) {
  context.subscriptions.push(
    vscode.commands.registerCommand(
      "phx-port.openInBrowser",
      async (uri?: vscode.Uri) => {
        const folder = resolveFolder(uri);
        if (!folder) {
          vscode.window.showErrorMessage(
            "phx-port: Right-click a folder in the Explorer, or open a single-folder workspace."
          );
          return;
        }
        try {
          const port = await getPort(folder);
          const url = vscode.Uri.parse(`http://localhost:${port}`);
          await vscode.env.openExternal(url);
        } catch (e: unknown) {
          const msg = e instanceof Error ? e.message : String(e);
          vscode.window.showErrorMessage(`phx-port: ${msg}`);
        }
      }
    ),

    vscode.commands.registerCommand(
      "phx-port.showPort",
      async (uri?: vscode.Uri) => {
        const folder = resolveFolder(uri);
        if (!folder) {
          vscode.window.showErrorMessage(
            "phx-port: Right-click a folder in the Explorer, or open a single-folder workspace."
          );
          return;
        }
        try {
          const port = await getPort(folder);
          const folderName = folder.split("/").pop() || folder;
          await vscode.window.showInformationMessage(
            `${folderName} → http://localhost:${port}`
          );
        } catch (e: unknown) {
          const msg = e instanceof Error ? e.message : String(e);
          vscode.window.showErrorMessage(`phx-port: ${msg}`);
        }
      }
    )
  );
}

export function deactivate() {}
