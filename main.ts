import { App, Editor, Plugin, PluginSettingTab, Setting } from 'obsidian';
import * as crypto from 'crypto';

interface EditorChangeTrackerSettings {
    keyPath: string; 
    isScript: boolean; 
}

const DEFAULT_SETTINGS: EditorChangeTrackerSettings = {
    keyPath: '', 
    isScript: false
};

class FileState {
    previousContent: string = '';
    lastLogTime: number | null = null;
    logBuffer: string[] = [];
    writeTimeout: number | null = null;
    keyPressMap: Map<string, number> = new Map();

    constructor(public filePath: string) {}

    reset() {
        this.previousContent = '';
        this.lastLogTime = null;
        this.logBuffer = [];
        if (this.writeTimeout !== null) {
            window.clearTimeout(this.writeTimeout);
            this.writeTimeout = null;
        }
        this.keyPressMap.clear();
    }
}

export default class EditorChangeTracker extends Plugin {
    settings: EditorChangeTrackerSettings;
    private privateKey: string | null = null;
    private fileStates: Map<string, FileState> = new Map();
    private activeFilePath: string | null = null;

    async onload() {
        await this.loadSettings();
        
        if (!this.settings.isScript) {
            try {
                let privateKey = await this.app.vault.adapter.read(this.settings.keyPath);
                
                privateKey = privateKey.replace(/\r\n/g, '\n').trim();
                if (!privateKey.startsWith('-----BEGIN PRIVATE KEY-----\n')) {
                    privateKey = '-----BEGIN PRIVATE KEY-----\n' + privateKey;
                }
                if (!privateKey.endsWith('\n-----END PRIVATE KEY-----')) {
                    privateKey = privateKey + '\n-----END PRIVATE KEY-----';
                }
                
                this.privateKey = privateKey;
            } catch (error) {
                console.error('Failed to load private key:', error);
                throw new Error('Failed to load private key: ' + error.message);
            }
        }

        // Register for file open events
        this.registerEvent(
            this.app.workspace.on('file-open', async (file) => {
                if (file) {
                    // If there was a previously active file, save its state before switching
                    if (this.activeFilePath && this.activeFilePath !== file.path) {
                        await this.writeLogBufferToFile(this.fileStates.get(this.activeFilePath)!);
                    }
                    
                    this.activeFilePath = file.path;
                    if (!this.fileStates.has(file.path)) {
                        const fileState = new FileState(file.path);
                        this.fileStates.set(file.path, fileState);
                        // Initialize the previous content with the current file content
                        fileState.previousContent = await this.app.vault.read(file);
                    }
                    await this.checkLogfileConsistency();
                } else {
                    // File is being closed
                    if (this.activeFilePath) {
                        const fileState = this.fileStates.get(this.activeFilePath);
                        if (fileState) {
                            // Write any pending changes before removing the state
                            await this.writeLogBufferToFile(fileState);
                            fileState.reset();
                            this.fileStates.delete(this.activeFilePath);
                        }
                    }
                    this.activeFilePath = null;
                }
            })
        );

        this.registerEvent(
            this.app.workspace.on('editor-change', (editor: Editor, info: any) => {
                const file = this.app.workspace.getActiveFile();
                if (file) {
                    this.activeFilePath = file.path;
                    if (!this.fileStates.has(file.path)) {
                        this.fileStates.set(file.path, new FileState(file.path));
                    }
                    const fileState = this.fileStates.get(file.path)!;
                    const currentContent = editor.getValue();
                    const cursorPosition = editor.getCursor();
                    this.logChange(fileState, currentContent, cursorPosition);
                    fileState.previousContent = currentContent;
                }
            })
        );

        this.registerDomEvent(document, 'keydown', (event: KeyboardEvent) => {
            if (!this.activeFilePath) return;
            const fileState = this.fileStates.get(this.activeFilePath);
            if (!fileState) return;

            const key = event.key;
            if (!fileState.keyPressMap.has(key)) {
                fileState.keyPressMap.set(key, window.performance.now());
            }
        });

        this.registerDomEvent(document, 'keyup', (event: KeyboardEvent) => {
            if (!this.activeFilePath) return;
            const fileState = this.fileStates.get(this.activeFilePath);
            if (!fileState) return;

            const key = event.key;
            if (fileState.keyPressMap.has(key)) {
                setTimeout(() => {
                    fileState.keyPressMap.delete(key)
                }, 1000);
            }
        });

        // Clean up stale key presses for all files periodically
        setInterval(() => {
            for (const fileState of this.fileStates.values()) {
                this.cleanupStaleKeyPressTimes(fileState);
            }
        }, 60000);

        // Add file rename event handler
        this.registerEvent(
            this.app.vault.on('rename', async (file, oldPath) => {
                if (this.fileStates.has(oldPath)) {
                    // Get the old file state
                    const fileState = this.fileStates.get(oldPath)!;
                    
                    // Write any pending changes before moving
                    await this.writeLogBufferToFile(fileState);
                    
                    // Update the file state with new path
                    fileState.filePath = file.path;
                    this.fileStates.delete(oldPath);
                    this.fileStates.set(file.path, fileState);
                    
                    // Move the log file to match the new file path
                    const oldLogPath = this.getLogFilePathForPath(oldPath);
                    const newLogPath = this.getLogFilePathForPath(file.path);
                    
                    if (oldLogPath && newLogPath) {
                        try {
                            // Check if old log file exists
                            if (await this.app.vault.adapter.exists(oldLogPath)) {
                                // Read old log content
                                const logContent = await this.app.vault.adapter.read(oldLogPath);
                                // Write to new location
                                await this.app.vault.adapter.write(newLogPath, logContent);
                                // Delete old log file
                                await this.app.vault.adapter.remove(oldLogPath);
                            }
                        } catch (error) {
                            console.error('Error moving log file:', error);
                        }
                    }
                    
                    if (this.activeFilePath === oldPath) {
                        this.activeFilePath = file.path;
                    }
                }
            })
        );

        this.addSettingTab(new EditorChangeTrackerSettingTab(this.app, this));
    }

    // Add helper method to get log file path for any file path
    getLogFilePathForPath(filePath: string): string | null {
        if (!filePath) return null;
        
        // Get the vault root path
        const vaultRoot = this.app.vault.configDir;
        
        // Get relative path from vault root
        const relativePath = filePath.startsWith(vaultRoot) ? 
            filePath.slice(vaultRoot.length + 1) : 
            filePath;
            
        // Split path into directory and filename
        const lastSlashIndex = relativePath.lastIndexOf('/');
        const directory = lastSlashIndex >= 0 ? relativePath.slice(0, lastSlashIndex + 1) : '';
        const filename = lastSlashIndex >= 0 ? relativePath.slice(lastSlashIndex + 1) : relativePath;
            
        // Create log file path by adding dot prefix to filename
        const logFileName = directory + '.' + filename.replace(/\.[^/.]+$/, '') + '.log';
        return logFileName;
    }

    // Update the existing getLogFilePath method to use the helper
    getLogFilePath(): string | null {
        if (!this.activeFilePath) return null;
        return this.getLogFilePathForPath(this.activeFilePath);
    }

    async checkLogfileConsistency() {
        const logFilePath = this.getLogFilePath();
        if (!logFilePath) return;

        try {
            const logContent = await this.app.vault.adapter.read(logFilePath);

            const hashMatch = logContent.match(/HASH: (.+)\n/);
            const signatureMatch = logContent.match(/SIGNATURE: (.+)\n/);

            if (hashMatch && signatureMatch) {
                const lastHash = hashMatch[1];
                const lastSignature = signatureMatch[1];

                const cleanedLogContent = logContent.replace(/\nHASH: .*\nSIGNATURE: .*\n$/, '');
                
                const calculatedHash = crypto.createHash('sha256').update(cleanedLogContent).digest('hex');
                const verify = crypto.createVerify('sha256');
                verify.update(calculatedHash);
				
                if (!this.settings.isScript && !this.privateKey) {
                    throw new Error('Private key not loaded');
                }

                const isSignatureValid = this.settings.isScript ? 
                    await this.verifyWithExternalScript(calculatedHash, lastSignature) :
                    verify.verify(this.privateKey!, lastSignature, 'hex');

                if (calculatedHash !== lastHash || !isSignatureValid) {
                    await this.fixLogfileInconsistency(cleanedLogContent, logFilePath);
                }
            }

            await this.checkTextConsistency(logFilePath);
        } catch (error) {
            // If the file doesn't exist, create it with initial content
            if (error.code === 'ENOENT') {
                const file = this.app.workspace.getActiveFile();
                if (file) {
                    const currentContent = await this.app.vault.read(file);
                    const initialLogEntry = `[MACHINE] @0 +${this.escapeText(currentContent)}\n`;
                    
                    const hash = crypto.createHash('sha256').update(initialLogEntry).digest('hex');
                    const sign = crypto.createSign('sha256');
                    sign.update(hash);
                    const signature = this.settings.isScript ? 
                        await this.signWithExternalScript(hash) :
                        sign.sign(this.privateKey!, 'hex');

                    const finalLogContent = `${initialLogEntry}\nHASH: ${hash}\nSIGNATURE: ${signature}\n`;
                    await this.app.vault.adapter.write(logFilePath, finalLogContent);
                }
            } else {
                console.error('Error checking logfile consistency:', error);
            }
        }
    }

    async fixLogfileInconsistency(cleanedLogContent: string, logFilePath: string) {
        const machineLogEntry = `[MACHINE] @0 +Logfile inconsistency detected and fixed.\n`;
        const fixedLogContent = `${cleanedLogContent}${machineLogEntry}`;

        
        const newHash = crypto.createHash('sha256').update(fixedLogContent).digest('hex');
        const sign = crypto.createSign('sha256');
        sign.update(newHash);
        const newSignature = sign.sign(this.privateKey!, 'hex');

        
        const finalLogContent = `${fixedLogContent}\nHASH: ${newHash}\nSIGNATURE: ${newSignature}\n`;

        
        await this.app.vault.adapter.write(logFilePath, finalLogContent);
    }

    async checkTextConsistency(logFilePath: string) {
        try {
            const logContent = await this.app.vault.adapter.read(logFilePath);
            const reconstructedText = this.reconstructTextFromLog(logContent);

            let actualContent: string;
            try {
                actualContent = await this.app.vault.adapter.read(this.activeFilePath!);
            } catch (error) {
                console.error(`Error reading current file content from ${this.activeFilePath}:`, error);
                throw new Error(`Failed to read current file content: ${error.message}`);
            }

            if (reconstructedText !== actualContent) {
                await this.fixTextInconsistency(logContent, reconstructedText, actualContent, logFilePath);
            }
        } catch (error) {
            console.error('Error during text consistency check:', error);
            // Re-throw the error to allow proper handling by the caller
            throw error;
        }
    }

    reconstructTextFromLog(logContent: string): string {
        let text = '';
        const lines = logContent.split('\n');

        for (const line of lines) {
            // Skip empty lines or lines with hash/signature
            if (!line || line.startsWith('HASH:') || line.startsWith('SIGNATURE:')) {
                continue;
            }

            let match: RegExpMatchArray | null;

            // Format 1: [MACHINE] @position +-text
            if ((match = line.match(/^\[MACHINE\] @(\d+) ([+-])(.*)$/))) {
                const [, position, type, changeText] = match;
                const pos = parseInt(position, 10);
                const unescapedText = this.unescapeText(changeText);

                if (type === '+') {
                    text = text.slice(0, pos) + unescapedText + text.slice(pos);
                } else if (type === '-') {
                    text = text.slice(0, pos) + text.slice(pos + unescapedText.length);
                }
            }
            // Format 2: [ISO_TIMESTAMP] {holdTime} @position +-text
            else if ((match = line.match(/^\[\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z\] \{(\d+)\} @(\d+) ([+-])(.*)$/))) {
                const [, , position, type, changeText] = match;
                const pos = parseInt(position, 10);
                const unescapedText = this.unescapeText(changeText);

                if (type === '+') {
                    text = text.slice(0, pos) + unescapedText + text.slice(pos);
                } else if (type === '-') {
                    text = text.slice(0, pos) + text.slice(pos + unescapedText.length);
                }
            }
            // Format 3: +relativeTime {holdTime} @position +-text
            else if ((match = line.match(/^\+(\d+) \{(\d+)\} @(\d+) ([+-])(.*)$/))) {
                const [, , , position, type, changeText] = match;
                const pos = parseInt(position, 10);
                const unescapedText = this.unescapeText(changeText);

                if (type === '+') {
                    text = text.slice(0, pos) + unescapedText + text.slice(pos);
                } else if (type === '-') {
                    text = text.slice(0, pos) + text.slice(pos + unescapedText.length);
                }
            }
        }

        return text;
    }

    private unescapeText(text: string): string {
        return text
            .replace(/\\n/g, '\n')
            .replace(/\\([+@\[\]\\])/g, '$1');
    }

    async fixTextInconsistency(logContent: string, reconstructedText: string, actualContent: string, logFilePath: string) {
        const diffs = this.calculateDiffForFixTextInconsistency(reconstructedText, actualContent);

        if (diffs.length > 0) {
            // Clean up existing hash and signature before appending fixes
            let fixedLogContent = logContent.replace(/\nHASH: .*\nSIGNATURE: .*\n$/, '');
            
            for (const diff of diffs) {
                const { type, text, position } = diff;
                const machineLogEntry = `[MACHINE] @${position} ${type}${this.escapeText(text)}\n`;
                fixedLogContent += machineLogEntry;
            }

            const newHash = crypto.createHash('sha256').update(fixedLogContent).digest('hex');
            const sign = crypto.createSign('sha256');
            sign.update(newHash);
            const newSignature = sign.sign(this.privateKey!, 'hex');

            const finalLogContent = `${fixedLogContent}\nHASH: ${newHash}\nSIGNATURE: ${newSignature}\n`;

            await this.app.vault.adapter.write(logFilePath, finalLogContent);
        }
    }

    logChange(fileState: FileState, currentContent: string, cursorPosition: { line: number, ch: number }) {
        const now = Date.now();
        let logEntry = '';
        if (fileState.lastLogTime === null) {
            logEntry = `[${new Date(now).toISOString()}] `;
        } else {
            const timeDiff = now - fileState.lastLogTime;
            if (timeDiff > 60000) {
                logEntry = `[${new Date(now).toISOString()}] `;
            } else {
                logEntry = `+${timeDiff} `;
            }
        }

        const diff = this.calculateDiffForLogChange(fileState.previousContent, currentContent, cursorPosition);

        if (diff) {
            const { type, text, position } = diff;
            const keyHoldTime = this.calculateKeyHoldTime(fileState, text);
            logEntry += `{${keyHoldTime}} @${position} ${type}${this.escapeText(text)}\n`;
            fileState.logBuffer.push(logEntry);
            fileState.lastLogTime = now;
        }
        
        this.debounceWriteToFile(fileState);
    }

    debounceWriteToFile(fileState: FileState) {
        if (fileState.writeTimeout) {
            clearTimeout(fileState.writeTimeout);
        }

        fileState.writeTimeout = window.setTimeout(() => {
            this.writeLogBufferToFile(fileState);
        }, 1000);
    }

    async writeLogBufferToFile(fileState: FileState) {
        if (fileState.logBuffer.length === 0) return;

        const logFilePath = this.getLogFilePath();
        if (!logFilePath) return;

        const logContent = fileState.logBuffer.join('');
        fileState.logBuffer = [];

        let existingLogContent = '';
        try {
            existingLogContent = await this.app.vault.adapter.read(logFilePath);
        } catch (error) {
            
        }

        const cleanedLogContent = existingLogContent.replace(/\nHASH: .*\nSIGNATURE: .*\n/g, '');

        const fullLogContent = cleanedLogContent + logContent;

        const hash = crypto.createHash('sha256').update(fullLogContent).digest('hex');

        let signature: string;
        try {
            if (this.settings.isScript) {
                signature = await this.signWithExternalScript(hash);
            } else {
                if (!this.privateKey) {
                    throw new Error('Private key not loaded');
                }
                const sign = crypto.createSign('sha256');
                sign.update(hash);
                signature = sign.sign(this.privateKey, 'hex');
            }
        } catch (err) {
            console.error('Failed to sign the hash:', err);
            throw new Error('Signing failed: ' + err.message);
        }

        const finalLogContent = `${fullLogContent}\nHASH: ${hash}\nSIGNATURE: ${signature}\n`;

        await this.app.vault.adapter.write(logFilePath, finalLogContent);
    }

    private async signWithExternalScript(hash: string): Promise<string> {
        return new Promise(async (resolve, reject) => {
            try {
                // Validate that the script path is within the vault
                const normalizedPath = this.app.vault.adapter.getResourcePath(this.settings.keyPath);
                const vaultRoot = this.app.vault.configDir;
                
                if (!normalizedPath.startsWith(vaultRoot)) {
                    throw new Error('Script must be located within the Obsidian vault');
                }

                // Verify the script exists
                const exists = await this.app.vault.adapter.exists(this.settings.keyPath);
                if (!exists) {
                    throw new Error('Script file does not exist');
                }

                // Read and validate script content
                const scriptContent = await this.app.vault.adapter.read(this.settings.keyPath);
                if (scriptContent.length > 10000) { // Reasonable size limit
                    throw new Error('Script file is too large');
                }

                // Basic script content validation
                if (!/^[\x20-\x7E\n\r\t]*$/.test(scriptContent)) {
                    throw new Error('Script contains invalid characters');
                }

                // Use spawn instead of exec for better security
                const { spawn } = require('child_process');
                const child = spawn(normalizedPath, [hash], {
                    cwd: vaultRoot,
                    shell: false,
                    timeout: 5000, // 5 second timeout
                    env: {}, // No environment variables passed
                    stdio: ['ignore', 'pipe', 'pipe']
                });

                let stdout = '';
                let stderr = '';

                child.stdout.on('data', (data: Buffer) => {
                    stdout += data.toString();
                });

                child.stderr.on('data', (data: Buffer) => {
                    stderr += data.toString();
                });

                child.on('error', (error: Error) => {
                    reject(new Error(`Script execution failed: ${error.message}`));
                });

                child.on('close', (code: number) => {
                    if (code !== 0) {
                        reject(new Error(`Script exited with code ${code}: ${stderr}`));
                        return;
                    }
                    resolve(stdout.trim());
                });
            } catch (error) {
                reject(new Error(`Script validation failed: ${error.message}`));
            }
        });
    }

    calculateDiffForLogChange(previous: string | undefined, current: string | undefined, cursorPosition: { line: number, ch: number }): { type: string, text: string, position: number } | null {
        // Handle undefined/null inputs
        if (previous == "" && current) {
            return {
                type: '+',
                text: current,
                position: 0
            };
        }
        if (!previous || !current) {
            return null;
        }

        const cursorOffset = this.getCursorOffset(previous, cursorPosition);

        // Focus on a small window around cursor for performance
        const windowSize = 100; // Increased window size to better handle multiline changes
        const start = Math.max(0, cursorOffset - windowSize);
        const end = Math.min(
            Math.min(previous.length, current.length),
            cursorOffset + windowSize
        );

        // Find first difference in the window
        for (let i = start; i < end; i++) {
            if (previous[i] !== current[i]) {
            // Handle deletion
            if (current.length < previous.length) {
                    // Find how many chars were deleted
                let j = 0;
                while (i + j < previous.length && 
                           (i >= current.length || previous[i + j] !== current[i])) {
                    j++;
                }
                return {
                    type: '-',
                    text: previous.slice(i, i + j),
                    position: i
                };
            }
            // Handle insertion
                else if (current.length > previous.length) {
                    // Find how many chars were inserted
                let j = 0;
                while (i + j < current.length && 
                           (i >= previous.length || current[i + j] !== previous[i])) {
                    j++;
                }
                return {
                    type: '+',
                    text: current.slice(i, i + j),
                    position: i
                };
            }
                // Handle single char replacement
        else {
                    // Look for a sequence of changed characters
                let j = 0;
                    while (i + j < current.length && 
                           i + j < previous.length && 
                           current[i + j] !== previous[i + j]) {
                    j++;
                }
                return {
                    type: '+',
                    text: current.slice(i, i + j),
                    position: i
                };
            }
            }
        }

        // Handle appending at end of file
        if (current.length > previous.length && 
            current.startsWith(previous)) {
            return {
                type: '+',
                text: current.slice(previous.length),
                position: previous.length
            };
        }

        return null;
    }
    
    calculateDiffForFixTextInconsistency(previous: string, current: string): { type: string, text: string, position: number }[] {
        const diffs: { type: string, text: string, position: number }[] = [];
        let i = 0;
        let j = 0;

        while (i < previous.length || j < current.length) {
            if (i < previous.length && j < current.length && previous[i] === current[j]) {
                i++;
                j++;
            } else {
                // Handle additions
                if (j < current.length && (i >= previous.length || previous[i] !== current[j])) {
                    const startPos = i;
                    let addedText = '';
                    
                    // Collect consecutive additions
                    while (j < current.length && (i >= previous.length || previous[i] !== current[j])) {
                        addedText += current[j];
                        j++;
                    }
                    
                    diffs.push({ type: '+', text: addedText, position: startPos });
                }
                // Handle deletions 
                else if (i < previous.length && (j >= current.length || previous[i] !== current[j])) {
                    const startPos = i;
                    let removedText = '';
                    
                    // Collect consecutive deletions
                    while (i < previous.length && (j >= current.length || previous[i] !== current[j])) {
                        removedText += previous[i];
                        i++;
                    }
                    
                    diffs.push({ type: '-', text: removedText, position: startPos });
                }
            }
        }

        return diffs;
    }

    getCursorOffset(text: string | undefined, cursorPosition: { line: number, ch: number }): number {
        // Handle undefined/null text
        if (!text) {
            return 0;
        }

        const lines = text.split('\n');
        let offset = 0;

        // Ensure we don't go beyond the actual number of lines
        const maxLine = Math.min(cursorPosition.line, lines.length - 1);
        for (let i = 0; i < maxLine; i++) {
            offset += (lines[i]?.length ?? 0) + 1; // Use optional chaining and nullish coalescing
        }

        // Add the final line's offset, ensuring we don't exceed the line length
        if (lines[maxLine]) {
            offset += Math.min(cursorPosition.ch, lines[maxLine].length);
        }

        return offset;
    }

    escapeText(text: string): string {
        return text
            .replace(/[+@\[\]\\]/g, '\\$&')  // Escape special characters
            .replace(/\n/g, '\\n');  // Escape newlines
    }

    async loadSettings() {
        this.settings = Object.assign({}, DEFAULT_SETTINGS, await this.loadData());
        
        
        if (!this.settings.keyPath) {
            this.settings.keyPath = '.obsidian/private_key.pem';
            await this.saveSettings();
        }
        
        try {
            
            const keyExists = await this.app.vault.adapter.exists(this.settings.keyPath);
            if (!keyExists || !(await this.validatePrivateKey(this.settings.keyPath))) {
                await this.generateAndSavePrivateKey();
            }
        } catch (error) {
            console.error('Error checking/generating private key:', error);
            throw new Error('Failed to initialize private key: ' + error.message);
        }
    }

    private async generateAndSavePrivateKey(): Promise<void> {
        try {
            const { generateKeyPair } = require('crypto');
            const { promisify } = require('util');
            const generateKeyPairAsync = promisify(generateKeyPair);

            const { privateKey, publicKey } = await generateKeyPairAsync('rsa', {
                modulusLength: 2048,
                publicKeyEncoding: {
                    type: 'spki',
                    format: 'pem'
                },
                privateKeyEncoding: {
                    type: 'pkcs8',
                    format: 'pem',
                    cipher: undefined,  
                    passphrase: undefined  
                }
            });

            // Format and save private key
            const formattedPrivateKey = privateKey.replace(/\r\n/g, '\n').trim() + '\n';
            await this.app.vault.adapter.write(this.settings.keyPath, formattedPrivateKey);
            
            // Save public key alongside private key
            const publicKeyPath = this.settings.keyPath.replace('.pem', '.pub.pem').replace('private', 'public');
            const formattedPublicKey = publicKey.replace(/\r\n/g, '\n').trim() + '\n';
            await this.app.vault.adapter.write(publicKeyPath, formattedPublicKey);
            
            console.log('Generated and saved new private key at:', this.settings.keyPath);
            console.log('Generated and saved new public key at:', publicKeyPath);
        } catch (error) {
            console.error('Failed to generate keys:', error);
            throw new Error('Failed to generate keys: ' + error.message);
        }
    }

    
    private async validatePrivateKey(keyPath: string): Promise<boolean> {
        try {
            const privateKey = await this.app.vault.adapter.read(keyPath);
            
            
            const pemRegex = /^-----BEGIN PRIVATE KEY-----\n[\s\S]*\n-----END PRIVATE KEY-----\n?$/;
            if (!pemRegex.test(privateKey.trim())) {
                console.error('Invalid private key format');
                return false;
            }

            
            const sign = crypto.createSign('sha256');
            sign.update('test');
            sign.sign(privateKey, 'hex');
            
            return true;
        } catch (error) {
            console.error('Private key validation failed:', error);
            return false;
        }
    }

    async saveSettings() {
        await this.saveData(this.settings);
    }

    cleanupStaleKeyPressTimes(fileState: FileState) {
        const now = Date.now();
        for (const [key, startTime] of fileState.keyPressMap.entries()) {
            if (startTime === -1 || now - startTime > 60000) {
                fileState.keyPressMap.delete(key);
            }
        }
    }

    calculateKeyHoldTime(fileState: FileState, text: string): number {
        let keyHoldTime = 0;

        for (const char of text) {
            if (fileState.keyPressMap.has(char)) {
                const keyPressStartTime = fileState.keyPressMap.get(char)!;
                if (keyPressStartTime !== -1) {
                    keyHoldTime += window.performance.now() - keyPressStartTime;
                }
                fileState.keyPressMap.delete(char);
            }
        }

        // Convert to microseconds (1 millisecond = 1000 microseconds)
        return Math.round(keyHoldTime * 1000);
    }

    private async verifyWithExternalScript(hash: string, signature: string): Promise<boolean> {
        return new Promise(async (resolve, reject) => {
            try {
                // Validate that the script path is within the vault
                const normalizedPath = this.app.vault.adapter.getResourcePath(this.settings.keyPath);
                const vaultRoot = this.app.vault.configDir;
                
                if (!normalizedPath.startsWith(vaultRoot)) {
                    throw new Error('Script must be located within the Obsidian vault');
                }

                // Verify the script exists
                const exists = await this.app.vault.adapter.exists(this.settings.keyPath);
                if (!exists) {
                    throw new Error('Script file does not exist');
                }

                // Read and validate script content
                const scriptContent = await this.app.vault.adapter.read(this.settings.keyPath);
                if (scriptContent.length > 10000) { // Reasonable size limit
                    throw new Error('Script file is too large');
                }

                // Basic script content validation
                if (!/^[\x20-\x7E\n\r\t]*$/.test(scriptContent)) {
                    throw new Error('Script contains invalid characters');
                }

                // Use spawn instead of exec for better security
                const { spawn } = require('child_process');
                const child = spawn(normalizedPath, [hash, signature], {
                    cwd: vaultRoot,
                    shell: false,
                    timeout: 5000, // 5 second timeout
                    env: {}, // No environment variables passed
                    stdio: ['ignore', 'pipe', 'pipe']
                });

                let stdout = '';
                let stderr = '';

                child.stdout.on('data', (data: Buffer) => {
                    stdout += data.toString();
                });

                child.stderr.on('data', (data: Buffer) => {
                    stderr += data.toString();
                });

                child.on('error', (error: Error) => {
                    reject(new Error(`Script execution failed: ${error.message}`));
                });

                child.on('close', (code: number) => {
                    if (code !== 0) {
                        reject(new Error(`Script exited with code ${code}: ${stderr}`));
                        return;
                    }
                    resolve(stdout.trim().toLowerCase() === 'true');
                });
            } catch (error) {
                reject(new Error(`Script validation failed: ${error.message}`));
            }
        });
    }

    async onunload() {
        // Write any pending log buffer entries before cleanup
        const writePromises = Array.from(this.fileStates.values()).map(async (fileState) => {
            if (fileState.writeTimeout !== null) {
                clearTimeout(fileState.writeTimeout);
                fileState.writeTimeout = null;
            }
            // Write any remaining log buffer entries
            await this.writeLogBufferToFile(fileState);
        });

        // Wait for all writes to complete
        await Promise.all(writePromises);
        
        // Clear the file states
        this.fileStates.clear();
    }
}

class EditorChangeTrackerSettingTab extends PluginSettingTab {
    plugin: EditorChangeTracker;

    constructor(app: App, plugin: EditorChangeTracker) {
        super(app, plugin);
        this.plugin = plugin;
    }

    display(): void {
        const { containerEl } = this;

        containerEl.empty();

        new Setting(containerEl)
            .setName('Key Path')
            .setDesc('Path to private key file or signing script')
            .addText(text => text
                .setPlaceholder('Enter path to key file or script')
                .setValue(this.plugin.settings.keyPath)
                .onChange(async (value) => {
                    this.plugin.settings.keyPath = value;
                    await this.plugin.saveSettings();
                }));

        new Setting(containerEl)
            .setName('Use External Script')
            .setDesc('Enable if the path points to a signing script instead of a key file')
            .addToggle(toggle => toggle
                .setValue(this.plugin.settings.isScript)
                .onChange(async (value) => {
                    this.plugin.settings.isScript = value;
                    await this.plugin.saveSettings();
                }));
    }
}