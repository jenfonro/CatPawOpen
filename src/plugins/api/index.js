import adminPlugins from './admin.js';
import pan139Plugins from './pan139.js';
import panBaiduPlugins from './panBaidu.js';
import panQuarkPlugins from './panQuark.js';

export const apiPlugins = [
    ...(Array.isArray(adminPlugins) ? adminPlugins : []),
    ...(Array.isArray(pan139Plugins) ? pan139Plugins : []),
    ...(Array.isArray(panBaiduPlugins) ? panBaiduPlugins : []),
    ...(Array.isArray(panQuarkPlugins) ? panQuarkPlugins : []),
];

export default apiPlugins;

