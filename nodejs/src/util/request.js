import req from "./req.js";
// 引入qs模块
import qs from 'qs';

export async function request(reqUrl) {
    let res = await req(reqUrl, {
        method: 'get',
    });
    return res.data;
}

export async function post(reqUrl, data = {}) {
    let res = await req(reqUrl, {
        method: 'post',
        data: data,
    });
    return res.data;
}

/**
 * 合并原始链接的 query 参数并生成新的链接
 * @param {string} originalUrl - 原始带 query 的链接
 * @param {Object} newQuery - 要传递的新的 query 参数
 * @returns {string} - 拼接好的可以直接 curl 请求的链接
 */
export function mergeQuery(originalUrl, newQuery) {
    // 使用 URL 构造函数解析原始链接
    const url = new URL(originalUrl);

    // 解析原始 query 为对象
    const originalQuery = qs.parse(url.search, { ignoreQueryPrefix: true });

    // 合并新的 query，新的 query 会覆盖原始 query 中的相同键
    const mergedQuery = { ...originalQuery, ...newQuery };

    // 序列化合并后的 query
    const mergedQueryString = qs.stringify(mergedQuery);

    // 更新 URL 的 search 属性
    url.search = `?${mergedQueryString}`;

    // 返回拼接好的完整 URL
    return url.toString();
}