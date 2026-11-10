'use strict';
const { app, BrowserWindow, dialog, ipcMain, shell } = require('electron');
const path = require('node:path');
const fs = require('node:fs/promises');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const execFileAsync = promisify(execFile);
// ipcMain is undefined when this file is required by the test runner.
const ipc = typeof ipcMain?.handle === 'function' ? ipcMain.handle.bind(ipcMain) : () => {};
const { scanProjectRoot, kinds } = require('./scanner.cjs');
const { verifyFinding, reviewFindings } = require('./ai-review.cjs');
const isInside = (root, target) => { const rel = path.relative(root, target); return rel === '' || (!rel.startsWith(`..${path.sep}`) && rel !== '..' && !path.isAbsolute(rel)); };
const statePath = () => path.join(app.getPath('userData'), 'deepcheck-projects.json');
async function readProjects() { try { return JSON.parse(await fs.readFile(statePath(), 'utf8')); } catch { return []; } }
async function saveProjects(projects) { await fs.mkdir(path.dirname(statePath()), { recursive: true }); await fs.writeFile(statePath(), JSON.stringify(projects, null, 2), 'utf8'); }
function createWindow() {
  const win = new BrowserWindow({ width: 1440, height: 920, minWidth: 1000, minHeight: 680, backgroundColor: '#101112', title: 'DeepCheck', webPreferences: { preload: path.join(__dirname, 'preload.cjs'), contextIsolation: true, nodeIntegration: false } });
  if (process.env.VITE_DEV_SERVER_URL) win.loadURL(process.env.VITE_DEV_SERVER_URL); else win.loadFile(path.join(__dirname, '../dist/index.html'));
}
if (process.versions.electron && typeof ipcMain?.handle === 'function') {
  app.whenReady().then(() => { createWindow(); app.on('activate', () => { if (!BrowserWindow.getAllWindows().length) createWindow(); }); });
  app.on('window-all-closed', () => { if (process.platform !== 'darwin') app.quit(); });
}
// IPC handlers remain registered only in the app process; tests call scanProjectRoot directly.
ipc('pick-folder', async () => { const result = await dialog.showOpenDialog({ properties: ['openDirectory'] }); return result.canceled ? null : result.filePaths[0]; });
ipc('list-projects', readProjects);
async function persistProject(rootPath, kind) {
  if (!kinds.includes(kind)) throw new Error('Choose a project category');
  const root = path.resolve(rootPath); const stat = await fs.stat(root).catch(() => null);
  if (!stat?.isDirectory()) throw new Error('The selected folder no longer exists');
  const projects = await readProjects();
  if (projects.some(p => path.resolve(p.root).toLowerCase() === root.toLowerCase())) throw new Error('This project is already connected');
  const project = { id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`, name: path.basename(root), root, kind, addedAt: new Date().toISOString(), latestRun: null };
  projects.unshift(project); await saveProjects(projects); return project;
}
ipc('add-project', async (_event, payload) => {
  if (!payload || !kinds.includes(payload.kind) || typeof payload.root !== 'string') throw new Error('Choose a folder and project category');
  return persistProject(payload.root, payload.kind);
});
async function ensureGit() {
  try { await execFileAsync('git', ['--version'], { windowsHide: true }); return; } catch {}
  try { await execFileAsync('winget', ['install', '--id', 'Git.Git', '-e', '--source', 'winget', '--accept-package-agreements', '--accept-source-agreements'], { timeout: 300000, windowsHide: true }); } catch {}
  try { await execFileAsync('git', ['--version'], { windowsHide: true }); return; } catch {}
  throw new Error('Git is not installed. Install Git for Windows from https://git-scm.com/download/win, restart DeepCheck, then retry cloning.');
}
ipc('clone-repo', async (_event, payload) => {
  await ensureGit();
  const url = payload?.url;
  if (typeof url !== 'string' || !/^https:\/\/(github\.com|gitlab\.com|bitbucket\.org)\/[\w.-]+\/[\w.-]+(?:\.git)?$/.test(url)) throw new Error('Enter a public GitHub, GitLab, or Bitbucket repository URL');
  const target = path.join(app.getPath('userData'), 'repositories', `${Date.now()}`); await fs.mkdir(path.dirname(target), { recursive: true });
  try { await execFileAsync('git', ['clone', '--depth', '1', url, target], { timeout: 120000, windowsHide: true }); }
  catch (error) { throw new Error(`Git clone failed: ${error.stderr || error.message}`); }
  return persistProject(target, payload.kind);
});
ipc('remove-project', async (_event, id) => { const projects = await readProjects(); const index = projects.findIndex(p => p.id === id); if (index < 0) throw new Error('Project not found'); const [removed] = projects.splice(index, 1); await saveProjects(projects); return removed; });
ipc('open-data-folder', async () => { const error = await shell.openPath(app.getPath('userData')); if (error) throw new Error(error); return true; });
ipc('open-project', async (_event, id) => { const p = (await readProjects()).find(item => item.id === id); if (!p) throw new Error('Project not found'); const error = await shell.openPath(p.root); if (error) throw new Error(error); return true; });
ipc('scan-project', async (_event, id) => {
  const projects = await readProjects(); const project = projects.find(p => p.id === id); if (!project) throw new Error('Project not found');
  // A fresh source scan starts a new run; don't leave test output from the prior scan attached.
  if (project.latestRun) {
    delete project.latestRun.testResult;
    for (const finding of project.latestRun.findings || []) { delete finding.aiAssessment; delete finding.aiReviewError; }
    await saveProjects(projects);
  }
  const result = await scanProjectRoot(project.root, project.kind);
  result.projectId = project.id; project.latestRun = result; await saveProjects(projects);
  await reviewFindings(project.root, result.findings, { onFinding: () => saveProjects(projects) });
  await saveProjects(projects);
  return result;
});
ipc('verify-finding', async (_event, payload) => {
  const { projectId, findingId } = payload || {};
  const projects = await readProjects();
  const project = projects.find((item) => item.id === projectId);
  if (!project?.latestRun) throw new Error('Scan this project before verifying a finding.');
  const finding = project.latestRun.findings.find((item) => item.id === findingId);
  if (!finding) throw new Error('Finding is no longer present in the latest scan. Run a fresh scan.');
  const assessment = await verifyFinding(project.root, finding);
  finding.aiAssessment = assessment;
  await saveProjects(projects);
  return assessment;
});
ipc('run-project-tests', async (_event, id) => {
  const projects = await readProjects(); const project = projects.find(p => p.id === id); if (!project?.latestRun?.testCommand) throw new Error('No supported project test command was detected.');
  const command = project.latestRun.testCommand;
  const exec = (file, args) => execFileAsync(file, args, { cwd: project.root, timeout: 10 * 60 * 1000, windowsHide: true, maxBuffer: 2 * 1024 * 1024 });
  try {
    const result = command === 'npm test' ? await exec('cmd.exe', ['/d', '/s', '/c', 'npm test']) : command === 'python -m pytest' ? await exec('python', ['-m', 'pytest']) : command === 'cargo test' ? await exec('cargo', ['test']) : await exec('go', ['test', './...']);
    project.latestRun.testResult = { command, exitCode: 0, output: `${result.stdout}\n${result.stderr}`.trim().slice(-50000) };
  } catch (error) { project.latestRun.testResult = { command, exitCode: error.code ?? 1, output: `${error.stdout || ''}\n${error.stderr || error.message}`.trim().slice(-50000) }; }
  await saveProjects(projects); return project.latestRun.testResult;
});

module.exports = { scanProjectRoot, kinds };
