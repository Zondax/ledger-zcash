const fs = require('fs');
const path = require('path');

// Function to sanitize variable names by replacing invalid characters with underscores
function sanitizeVarName(fileName) {
    // Replace any non-alphanumeric characters (except underscore) with underscore
    return fileName.replace(/[^a-zA-Z0-9_]/g, '_');
}

function postBuild(filePaths, outputDir, mainFile) {
    // Ensure output directory exists
    if (!fs.existsSync(outputDir)) {
        fs.mkdirSync(outputDir, { recursive: true });
    }

    // Array to store generated file paths for package.json
    const generatedFiles = [];
    // Object to store export mappings
    const exportsMap = {};

    for (const filePath of filePaths) {
        const buf = fs.readFileSync(filePath);
        const hexString = buf.toString('hex');
        
        // Extract file name without extension and sanitize it for use as variable name
        const fileName = path.basename(filePath, path.extname(filePath));
        const varName = sanitizeVarName(fileName);
        
        // Create individual file content with CommonJS export
        const outputContent = `// This file contains binary data encoded as hexadecimal strings\n\n` +
            `// Hexadecimal representation of ${path.basename(filePath)}\n` +
            `const ${varName} = "${hexString}";\n\n` +
            `module.exports = ${varName};\n`;
        
        // Create individual output file path using just the filename with .js extension
        const outputFileName = path.basename(filePath) + '.js';
        const individualOutputPath = path.join(outputDir, outputFileName);
        
        fs.writeFileSync(individualOutputPath, outputContent);
        console.log("Generated hex file at: ", individualOutputPath);
        generatedFiles.push(outputFileName);

        // Create corresponding .d.ts file
        const typeContent = `declare const ${varName}: string;\n\nexport default ${varName};\n`;
        const typeFileName = path.basename(filePath) + '.d.ts';
        const typeOutputPath = path.join(outputDir, typeFileName);
        
        fs.writeFileSync(typeOutputPath, typeContent);
        console.log("Generated type file at: ", typeOutputPath);
        generatedFiles.push(typeFileName);

        // Add to exports map using just the base filename without extension
        const exportPath = `./${fileName}`;
        const typesPath = `./${typeFileName}`;
        exportsMap[exportPath] = {
            require: `./${outputFileName}`,
            import: `./${outputFileName}`,
            types: typesPath
        };
    }

    // Update package.json to include generated files and exports
    const packageJsonPath = path.join(outputDir, 'package.json');
    if (fs.existsSync(packageJsonPath)) {
        const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
        if (!packageJson.files) {
            packageJson.files = [];
        }
        
        // Add only new files that aren't already in the list
        for (const file of generatedFiles) {
            if (!packageJson.files.includes(file)) {
                packageJson.files.push(file);
            }
        }

        // Add exports field if it doesn't exist
        if (!packageJson.exports) {
            packageJson.exports = {};
        }

        // Merge new exports with existing ones
        const mainFileName = path.basename(mainFile, path.extname(mainFile)) + '.js';
        packageJson.exports = {
            ...packageJson.exports,
            ...exportsMap,
            '.': {
                require: `./${mainFileName}`,
                import: `./${mainFileName}`,
                types: `./${path.basename(mainFile, path.extname(mainFile))}.d.ts`
            }
        };

        // Set main entry point to the specified main file
        packageJson.main = mainFileName;
        
        // Modify the main file to use hex encoding instead of direct file reading
        const mainFilePath = path.join(outputDir, mainFileName);
        if (fs.existsSync(mainFilePath)) {
            const mainFileContent = fs.readFileSync(mainFilePath, 'utf8');
            const modifiedContent = mainFileContent.replace(
                /const path = require\('path'\)\.join\(__dirname, 'zcashtool_bg\.wasm'\);\nconst bytes = require\('fs'\)\.readFileSync\(path\);/g,
                `const bytesHex = require('./zcashtool_bg.wasm.js');\nconst bytes = Buffer.from(bytesHex, "hex");`
            );
            fs.writeFileSync(mainFilePath, modifiedContent);
            console.log("Modified main file to use hex encoding");
        }

        // Set package name
        packageJson.name = "@zondax/ledger-zcash-tools";
        
        fs.writeFileSync(packageJsonPath, JSON.stringify(packageJson, null, 2));
        console.log("Updated package.json files, exports fields, and main entry point");
    } else {
        console.warn("package.json not found in output directory, skipping files and exports update");
    }
}

// Get arguments from command line
const args = process.argv.slice(2);
if (args.length < 2) {
    console.error('Usage: node post_build.js <output_directory> <main_file> [<input_file2> ...]');
    process.exit(1);
}

const outputDir = args[0];
const mainFile = args[1];
const filesToProcess = args.slice(2);

postBuild(filesToProcess, outputDir, mainFile);