// 引入必要模块
import CryptoJS from 'crypto-js';
import pako from 'pako';
import { Buffer } from 'buffer';

/**
 * 随机生成加密和解密算法
 * @returns {Object} - 包含加密和解密函数的对象
 */
function createRandomEncryption() {
    // 可用的编码工具
    const tools = [
        {
            name: 'base64Encode',
            encode: (data) => Buffer.from(data).toString('base64'),
            decode: (data) => Buffer.from(data, 'base64').toString('utf-8')
        },
        {
            name: 'aesEncrypt',
            encode: (data, key) => CryptoJS.AES.encrypt(data, key).toString(),
            decode: (data, key) => CryptoJS.AES.decrypt(data, key).toString(CryptoJS.enc.Utf8)
        },
        {
            name: 'gzipCompress',
            encode: (data) => Buffer.from(pako.gzip(data)).toString('base64'),
            decode: (data) => pako.ungzip(Buffer.from(data, 'base64'), { to: 'string' })
        },
        {
            name: 'addRandomString',
            encode: (data) => {
                const length = Math.floor(Math.random() * 7) + 4; // 随机长度在4到10之间
                const randomStr = Math.random().toString(36).substring(2, 2 + length);
                addRandomStringTracker.push({ value: randomStr, position: addRandomStringTracker.length });
                return data + randomStr;
            },
            decode: (data) => {
                const { value } = addRandomStringTracker.pop();
                return data.slice(0, -value.length);
            }
        }
    ];

    // 跟踪插入的随机字符串
    const addRandomStringTracker = [];

    // 随机生成加密和解密的组合序列
    const encodeSequence = Array.from({ length: Math.floor(Math.random() * tools.length) + 1 }, () => {
        return tools[Math.floor(Math.random() * tools.length)];
    });

    // 生成加密函数
    const encrypt = (data, key = 'default_key') => {
        let encrypted = data;
        for (const tool of encodeSequence) {
            encrypted = tool.encode(encrypted, key);
        }
        return encrypted;
    };

    // 生成解密函数
    const decrypt = (data, key = 'default_key') => {
        let decrypted = data;
        for (const tool of encodeSequence.slice().reverse()) {
            decrypted = tool.decode(decrypted, key);
        }
        return decrypted;
    };

    // 返回加解密函数
    return {
        encrypt,
        decrypt,
        sequence: encodeSequence.map(tool => tool.name),
        randomStrings: addRandomStringTracker
    };
}

// 示例使用
const { encrypt, decrypt, sequence, randomStrings } = createRandomEncryption();
const originalText = 'Hello, world!';
const key = 'my_secret_key';

const encryptedText = encrypt(originalText, key);
console.log('加密算法顺序:', sequence);
console.log('插入的随机字符串:', randomStrings.map(({ value, position }) => `位置: ${position}, 值: ${value}`));
console.log('加密后的文本:', encryptedText);

const decryptedText = decrypt(encryptedText, key);
console.log('解密后的文本:', decryptedText);
