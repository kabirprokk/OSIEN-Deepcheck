'use strict';
const { contextBridge, ipcRenderer } = require('electron');
contextBridge.exposeInMainWorld('deepcheck', {
  pickFolder: () => ipcRenderer.invoke('pick-folder'),
  listProjects: () => ipcRenderer.invoke('list-projects'),
  addProject: (payload) => ipcRenderer.invoke('add-project', payload),
  cloneRepo: (payload) => ipcRenderer.invoke('clone-repo', payload),
  removeProject: (id) => ipcRenderer.invoke('remove-project', id),
  openDataFolder: () => ipcRenderer.invoke('open-data-folder'),
  scanProject: (id) => ipcRenderer.invoke('scan-project', id),
  verifyFinding: (payload) => ipcRenderer.invoke('verify-finding', payload),
  runProjectTests: (id) => ipcRenderer.invoke('run-project-tests', id),
});
