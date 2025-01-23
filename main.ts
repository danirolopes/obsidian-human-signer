import { App, Editor, Plugin, PluginSettingTab, Setting } from 'obsidian';
import * as crypto from 'crypto';

interface EditorChangeTrackerSettings {
    keyPath: string; // Path to private key file or signing script
    isScript: boolean; // Whether the path points to a signing script
}

const DEFAULT_SETTINGS: EditorChangeTrackerSettings = {
    keyPath: '', // User must provide their key/script path
    isScript: false
};

export default class EditorChangeTracker extends Plugin {
    settings: EditorChangeTrackerSettings;
    private previousContent: string = '';
    private lastLogTime: number | null = null;
    private logBuffer: string[] = []; // Buffer to store logs before writing to file
    private writeTimeout: number | null = null;
    private currentFilePath: string | null = null; // Path of the currently edited file

    async onload() {
        await this.loadSettings();

        // Register the editor change event
        this.registerEvent(
            this.app.workspace.on('editor-change', (editor: Editor, info: any) => {
                const file = this.app.workspace.getActiveFile();
                if (file) {
                    this.currentFilePath = file.path;
                    const currentContent = editor.getValue();
                    const cursorPosition = editor.getCursor(); // Get the cursor position
                    this.logChange(this.previousContent, currentContent, cursorPosition);
                    this.previousContent = currentContent; // Update the previous content
                }
            })
        );

        // Add a settings tab
        this.addSettingTab(new EditorChangeTrackerSettingTab(this.app, this));
    }

    // Get the logfile path based on the currently edited file
    getLogFilePath(): string | null {
        if (!this.currentFilePath) return null;

        // Generate the logfile name by replacing the file extension with .log and adding a dot
        const logFileName = `.${this.currentFilePath.replace(/\.[^/.]+$/, '')}.log`;
        return logFileName;
    }

    // Check logfile consistency on plugin load
    async checkLogfileConsistency() {
        const logFilePath = this.getLogFilePath();
        if (!logFilePath) return;

        try {
            const logContent = await this.app.vault.adapter.read(logFilePath);

            // Extract the last hash and signature from the logfile
            const hashMatch = logContent.match(/HASH: (.+)\n/);
            const signatureMatch = logContent.match(/SIGNATURE: (.+)\n/);

            if (hashMatch && signatureMatch) {
                const lastHash = hashMatch[1];
                const lastSignature = signatureMatch[1];

                // Remove the last hash and signature from the log content
                const cleanedLogContent = logContent.replace(/\nHASH: .*\nSIGNATURE: .*\n$/, '');

                // Calculate the hash of the cleaned log content
                const calculatedHash = crypto.createHash('sha256').update(cleanedLogContent).digest('hex');

                // Verify the hash and signature
                const verify = crypto.createVerify('sha256');
                verify.update(calculatedHash);
                const isSignatureValid = verify.verify(this.settings.privateKey, lastSignature, 'hex');

                if (calculatedHash !== lastHash || !isSignatureValid) {
                    // Logfile is inconsistent, fix it
                    await this.fixLogfileInconsistency(cleanedLogContent, logFilePath);
                }
            }

            // Reconstruct the text from the logfile and compare it with the actual file
            await this.checkTextConsistency(logFilePath);
        } catch (error) {
            // Logfile does not exist or is empty, ignore
        }
    }

    // Fix logfile inconsistency
    async fixLogfileInconsistency(cleanedLogContent: string, logFilePath: string) {
        const machineLogEntry = `[MACHINE] @0 +Logfile inconsistency detected and fixed.\n`;
        const fixedLogContent = `${cleanedLogContent}${machineLogEntry}`;

        // Recalculate the hash and signature for the fixed log content
        const newHash = crypto.createHash('sha256').update(fixedLogContent).digest('hex');
        const sign = crypto.createSign('sha256');
        sign.update(newHash);
        const newSignature = sign.sign(this.settings.privateKey, 'hex');

        // Append the new hash and signature
        const finalLogContent = `${fixedLogContent}\nHASH: ${newHash}\nSIGNATURE: ${newSignature}\n`;

        // Write the fixed log content to the file
        await this.app.vault.adapter.write(logFilePath, finalLogContent);
    }

    // Check text consistency between the logfile and the actual file
    async checkTextConsistency(logFilePath: string) {
        try {
            const logContent = await this.app.vault.adapter.read(logFilePath);

            // Reconstruct the text from the logfile
            const reconstructedText = this.reconstructTextFromLog(logContent);

            // Read the actual file content
            const actualContent = await this.app.vault.adapter.read(this.currentFilePath!);

            // Compare the reconstructed text with the actual file content
            if (reconstructedText !== actualContent) {
                // Text is inconsistent, fix it
                await this.fixTextInconsistency(logContent, reconstructedText, actualContent, logFilePath);
            }
        } catch (error) {
            // File does not exist or is empty, ignore
        }
    }

    // Reconstruct the text from the logfile
    reconstructTextFromLog(logContent: string): string {
        let text = '';
        const lines = logContent.split('\n');

        for (const line of lines) {
            if (line.startsWith('+') || line.startsWith('-') || line.startsWith('[MACHINE]')) {
                const match = line.match(/^\[MACHINE\] @(\d+) ([+-])(.*)$/) ||
                              line.match(/^([+-])(\d+) @(\d+) (.*)$/);
                if (match) {
                    const type = match[2];
                    const position = parseInt(match[3], 10);
                    const changeText = match[4];

                    if (type === '+') {
                        text = text.slice(0, position) + changeText + text.slice(position);
                    } else if (type === '-') {
                        text = text.slice(0, position) + text.slice(position + changeText.length);
                    }
                }
            }
        }

        return text;
    }

    // Fix text inconsistency
    async fixTextInconsistency(logContent: string, reconstructedText: string, actualContent: string, logFilePath: string) {
        const diffs = this.calculateDiffForFixTextInconsistency(reconstructedText, actualContent);

        if (diffs.length > 0) {
            let fixedLogContent = logContent;
            for (const diff of diffs) {
                const { type, text, position } = diff;
                const machineLogEntry = `[MACHINE] @${position} ${type}${this.escapeText(text)}\n`;
                fixedLogContent += machineLogEntry;
            }

            // Recalculate the hash and signature for the fixed log content
            const newHash = crypto.createHash('sha256').update(fixedLogContent).digest('hex');
            const sign = crypto.createSign('sha256');
            sign.update(newHash);
            const newSignature = sign.sign(this.settings.privateKey, 'hex');

            // Append the new hash and signature
            const finalLogContent = `${fixedLogContent}\nHASH: ${newHash}\nSIGNATURE: ${newSignature}\n`;

            // Write the fixed log content to the file
            await this.app.vault.adapter.write(logFilePath, finalLogContent);
        }
    }

    // Log the change with timing and position
    logChange(previousContent: string, currentContent: string, cursorPosition: { line: number, ch: number }) {
        const now = Date.now();
        let logEntry = '';

        if (this.lastLogTime === null) {
            // Log the full timestamp if lastLogTime is null
            logEntry = `[${new Date(now).toISOString()}] `;
        } else {
            const timeDiff = now - this.lastLogTime;
            if (timeDiff > 60000) {
                // Log the full timestamp if the time difference is greater than 1 minute
                logEntry = `[${new Date(now).toISOString()}] `;
            } else {
                // Log the relative time difference
                logEntry = `+${timeDiff} `;
            }
        }

        // Calculate the difference between the previous and current content
        const diff = this.calculateDiffForLogChange(previousContent, currentContent, cursorPosition);

        // Add the change to the log buffer
        if (diff) {
            const { type, text, position } = diff;
            logEntry += `@${position} ${type}${this.escapeText(text)}\n`;
            this.logBuffer.push(logEntry);
        }

        // Update lastLogTime
        this.lastLogTime = now;

        // Debounce writing to file
        this.debounceWriteToFile();
    }

    // Debounce writing to file
    debounceWriteToFile() {
        if (this.writeTimeout) {
            clearTimeout(this.writeTimeout);
        }

        this.writeTimeout = window.setTimeout(() => {
            this.writeLogBufferToFile();
        }, 1000); // 1-second debounce
    }

    // Write the log buffer to file
    async writeLogBufferToFile() {
        if (this.logBuffer.length === 0) return;

        const logFilePath = this.getLogFilePath();
        if (!logFilePath) return;

        // Join the log buffer into a single string
        const logContent = this.logBuffer.join('');
        this.logBuffer = []; // Clear the buffer

        // Read the existing log file (if it exists)
        let existingLogContent = '';
        try {
            existingLogContent = await this.app.vault.adapter.read(logFilePath);
        } catch (error) {
            // File does not exist yet, ignore
        }

        // Remove previous hashes and signatures from the existing log content
        const cleanedLogContent = existingLogContent.replace(/\nHASH: .*\nSIGNATURE: .*\n/g, '');

        // Combine the cleaned existing log content with the new log content
        const fullLogContent = cleanedLogContent + logContent;

        // Calculate the hash of the full log content (excluding previous hashes and signatures)
        const hash = crypto.createHash('sha256').update(fullLogContent).digest('hex');

        let signature: string;
        try {
            if (this.settings.isScript) {
                // Use external script to sign the hash
                signature = await this.signWithExternalScript(hash);
            } else {
                // Read private key from file and sign
                const privateKey = await this.app.vault.adapter.read(this.settings.keyPath);
                const sign = crypto.createSign('sha256');
                sign.update(hash);
                signature = sign.sign(privateKey, 'hex');
            }
        } catch (err) {
            console.error('Failed to sign the hash. Please check your key file or signing script.');
            throw new Error('Signing failed: ' + err.message);
        }

        // Append the hash and signature to the log content
        const finalLogContent = `${fullLogContent}\nHASH: ${hash}\nSIGNATURE: ${signature}\n`;

        // Write the final log content to the file
        await this.app.vault.adapter.write(logFilePath, finalLogContent);
    }

    // New method to handle external script signing
    private async signWithExternalScript(hash: string): Promise<string> {
        return new Promise((resolve, reject) => {
            const { exec } = require('child_process');
            
            exec(`"${this.settings.keyPath}" "${hash}"`, (error: Error, stdout: string, stderr: string) => {
                if (error) {
                    console.error(`Signing script error: ${error}`);
                    reject(error);
                    return;
                }
                if (stderr) {
                    console.error(`Signing script stderr: ${stderr}`);
                }
                resolve(stdout.trim());
            });
        });
    }

    // Calculate the difference between two strings for logChange
    calculateDiffForLogChange(previous: string, current: string, cursorPosition: { line: number, ch: number }): { type: string, text: string, position: number } | null {
        const cursorOffset = this.getCursorOffset(previous, cursorPosition);

        // Find the first difference near the cursor
        let start = Math.max(0, cursorOffset - 100); // Look 100 characters before the cursor
        let end = Math.min(previous.length, cursorOffset + 100); // Look 100 characters after the cursor

        // Compare the text around the cursor
        for (let i = start; i < end; i++) {
            if (previous[i] !== current[i]) {
                // Determine if it's an addition or deletion
                if (current.length > previous.length) {
                    const addedText = current.slice(i, i + (current.length - previous.length));
                    return { type: '+', text: addedText, position: i };
                } else if (current.length < previous.length) {
                    const removedText = previous.slice(i, i + (previous.length - current.length));
                    return { type: '-', text: removedText, position: i };
                } else {
                    // Handle replacement (e.g., pasting over selected text)
                    const addedText = current.slice(i, i + 1);
                    const removedText = previous.slice(i, i + 1);
                    return { type: '+', text: addedText, position: i };
                }
            }
        }

        return null; // No change detected
    }

    // Calculate the difference between two strings for fixTextInconsistency
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
                    const addedText = current[j];
                    diffs.push({ type: '+', text: addedText, position: i });
                    j++;
                }
                // Handle deletions
                else if (i < previous.length && (j >= current.length || previous[i] !== current[j])) {
                    const removedText = previous[i];
                    diffs.push({ type: '-', text: removedText, position: i });
                    i++;
                }
            }
        }

        return diffs;
    }

    // Get the cursor offset in the text
    getCursorOffset(text: string, cursorPosition: { line: number, ch: number }): number {
        const lines = text.split('\n');
        let offset = 0;

        for (let i = 0; i < cursorPosition.line; i++) {
            offset += lines[i].length + 1; // +1 for the newline character
        }

        offset += cursorPosition.ch;
        return offset;
    }

    // Escape special characters in the text
    escapeText(text: string): string {
        return text.replace(/[+@\[\]]/g, '\\$&');
    }

    async loadSettings() {
        this.settings = Object.assign({}, DEFAULT_SETTINGS, await this.loadData());
        
        // If no key path is specified, use default path in .obsidian folder
        if (!this.settings.keyPath) {
            this.settings.keyPath = '.obsidian/private_key.pem';
            await this.saveSettings();
            
            // Check if key file exists, if not generate one
            try {
                await this.app.vault.adapter.read(this.settings.keyPath);
            } catch {
                await this.generateAndSavePrivateKey();
            }
        }
    }

    private async generateAndSavePrivateKey(): Promise<void> {
        try {
            // Generate key pair using Node's crypto module
            const { generateKeyPair } = require('crypto');
            const { promisify } = require('util');
            const generateKeyPairAsync = promisify(generateKeyPair);

            const { privateKey } = await generateKeyPairAsync('rsa', {
                modulusLength: 2048,
                publicKeyEncoding: {
                    type: 'spki',
                    format: 'pem'
                },
                privateKeyEncoding: {
                    type: 'pkcs8',
                    format: 'pem'
                }
            });

            // Save the private key
            await this.app.vault.adapter.write(this.settings.keyPath, privateKey);
            
            console.log('Generated and saved new private key at:', this.settings.keyPath);
        } catch (error) {
            console.error('Failed to generate private key:', error);
            throw new Error('Failed to generate private key: ' + error.message);
        }
    }

    async saveSettings() {
        await this.saveData(this.settings);
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