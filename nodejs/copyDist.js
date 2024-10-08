// Import required modules
import fs from 'fs';
import path from 'path';
import { execSync } from 'child_process';

// Check if the destination path is provided
if (process.argv.length < 3) {
    console.error('Usage: node script.js <destination_path>');
    process.exit(1);
}

// Get the destination path from command-line arguments
const destinationPath = process.argv[2];

// Resolve paths
const distPath = path.resolve(process.cwd(), 'dist');
const targetPath = path.resolve(destinationPath);

// Check if dist directory exists
if (!fs.existsSync(distPath)) {
    console.error(`Source directory does not exist: ${distPath}`);
    process.exit(1);
}

// Check if target directory exists
if (!fs.existsSync(targetPath)) {
    console.error(`Target directory does not exist: ${targetPath}`);
    process.exit(1);
}

// Copy files from dist to target
const copyFiles = (srcDir, destDir) => {
    const entries = fs.readdirSync(srcDir, { withFileTypes: true });

    entries.forEach((entry) => {
        const srcPath = path.join(srcDir, entry.name);
        const destPath = path.join(destDir, entry.name);

        if (entry.isDirectory()) {
            // Create directory if it doesn't exist
            if (!fs.existsSync(destPath)) {
                fs.mkdirSync(destPath);
            }
            // Recursively copy files
            copyFiles(srcPath, destPath);
        } else {
            // Copy file and overwrite if exists
            fs.copyFileSync(srcPath, destPath);
            console.log(`Copied: ${srcPath} -> ${destPath}`);
        }
    });
};

try {
    console.log(`Copying files from ${distPath} to ${targetPath}...`);
    copyFiles(distPath, targetPath);
    console.log('All files copied successfully.');
} catch (error) {
    console.error('Error during file copy:', error);
    process.exit(1);
}
