import net from 'net';
import {JSONPath} from 'jsonpath-plus';

export const jsonpath = {
    query(jsonObject, path) {
        return JSONPath({path: path, json: jsonObject})
    }
};

// 检查端口是否被占用
function checkPort(port) {
    return new Promise((resolve) => {
        const server = net.createServer();
        server.once('error', () => {
            resolve(false); // 端口被占用
        });
        server.once('listening', () => {
            server.close(() => resolve(true)); // 端口可用
        });
        server.listen(port);
    });
}

// 查找可用端口
export async function findAvailablePort(startPort) {
    let port = Number(startPort);
    while (!(await checkPort(port))) {
        port += 1; // 递增端口
    }
    return port;
}

export function extractTags(filename) {
    // 正则匹配方括号内的内容
    const regex = /\[(.*?)\]/g;
    const matches = [...filename.matchAll(regex)]; // 获取所有匹配项

    // 提取每个方括号中的单词
    const tags = matches.map(match => match[1].split(''));
    // 扁平化数组并去重
    return [...new Set(tags.flat())];
}

export function getRandomFromList(list) {
    // 将列表转换为数组
    const array = Array.isArray(list) ? list : Array.from(list);
    // 获取随机索引
    const randomIndex = Math.floor(Math.random() * array.length);
    // 返回随机选取的元素
    return array[randomIndex];
}

/**
 * 对数组进行随机乱序（Fisher-Yates 洗牌算法）
 * @param {Array} array - 需要乱序的数组
 * @returns {Array} - 返回乱序后的新数组
 */
export function shuffleArray(array) {
    const result = [...array]; // 创建数组副本，避免修改原数组
    for (let i = result.length - 1; i > 0; i--) {
        const randomIndex = Math.floor(Math.random() * (i + 1)); // 随机索引
        [result[i], result[randomIndex]] = [result[randomIndex], result[i]]; // 交换元素
    }
    return result;
}

// 示例
// console.log(extractTags('1[画]')); // 输出 ['画']
// console.log(extractTags('xxxx[书密]')); // 输出 ['书', '密']
// console.log(extractTags('2[书] 3[密]')); // 输出 ['书', '密']
// console.log(extractTags('3')); // 输出 ['书', '密']
