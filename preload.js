const { contextBridge, ipcRenderer } = require('electron')

contextBridge.exposeInMainWorld('electronAPI', {
    loginWithGoogle: () => ipcRenderer.invoke('google-login')
})