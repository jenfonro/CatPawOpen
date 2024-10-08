import {createServer} from 'http';
import os from 'os';
import {start} from './index.js';
import * as config from './index.config.js';
import axios from "axios";

globalThis.catServerFactory = (handle) => {
    let port = 0;
    const server = createServer((req, res) => {
        handle(req, res);
    });

    // 自动 GET 请求逻辑
    async function autoRequest(url) {
        try {
            const response = await axios.get(url); // 替换为目标接口
            console.log(`Auto-request successful: ${response.data.message || ''}`);
        } catch (error) {
            console.log(`Auto-request failed: ${error.message}`);
        }
    }

    server.on('listening', async () => {
        port = server.address().port;

        // Get local IP addresses
        const networkInterfaces = os.networkInterfaces();
        const addresses = [];
        for (const interfaceName in networkInterfaces) {
            for (const net of networkInterfaces[interfaceName]) {
                if (!net.internal && net.family === 'IPv4') {
                    addresses.push(net.address);
                }
            }
        }
        const localConfigUrl = `http://localhost:${port}/config`;

        console.log(`Server is running:`);
        console.log(`- Local:    ${localConfigUrl}`);
        if (addresses.length > 0) {
            console.log(`- Network:  http://${addresses[0]}:${port}/config`);
        }
        console.log(`- Node.js version: ${process.version}`);
        await autoRequest(localConfigUrl);
    });

    server.on('close', () => {
        console.log('Server closed on port ' + port);
    });

    return server;
};

globalThis.catDartServerPort = () => {
    return 0;
};

start(config.default);
