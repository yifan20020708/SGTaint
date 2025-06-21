const Koa = require('koa'); 
const koaBody = require('koa-body');
const error = require('koa-json-error');
const app = new Koa();
const routing = require('./routes');

// 错误处理中间件
app.use(error({
    postFormat: (err, { stack, ...rest }) => 
      process.env.NODE_ENV === 'production' ? rest : { stack, ...rest }  // 根据环境条件性地包含堆栈信息
  }));
// 解析请求体的中间件
app.use(koaBody());
// 将app实例传递给路由模块以设置路由
routing(app);
// 在30000端口启动服务器并输出成功日志
app.listen(30000, () => {
    console.log('Server is successfully running on port 30000');
  });