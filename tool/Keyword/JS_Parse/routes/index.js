const fs = require('fs');
const path = require('path');

module.exports = (app) => {
    fs.readdirSync(__dirname).forEach((routeFile) => {
      // 跳过'index.js'文件，因为它是入口文件
      if (routeFile === 'index.js') return;
      const routePath = path.join(__dirname, routeFile);
      const route = require(routePath);
      // 将路由的中间件及允许的方法注册到 app 上
      app.use(route.routes()).use(route.allowedMethods());
    });
  };