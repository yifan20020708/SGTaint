const Router = require('koa-router');
const router = new Router({ prefix: '/codeparse' });
const { jsparse } = require('../code_parser/js_parser');

// 定义POST路由来处理发送到'/codeparse'的请求
// 路由触发'jsparse'函数以执行代码解析逻辑
router.post('/', jsparse);
// 导出该路由实例，以便在应用程序的其他部分使用
module.exports = router;