// 导入解析 JavaScript 代码所需的模块
const { Parser } = require("acorn");             
const acornJsx = require("acorn-jsx")();         
const acornBigint = require("acorn-bigint");      
const esprima = require('esprima');                

// Codeparse类负责使用不同的解析引擎解析JavaScript代码
// 它支持Acorn（支持 JSX 和 BigInt）和Esprima
class Codeparse {
    async jsparse(ctx) {
        // 从请求体中提取引擎类型和JavaScript代码
        const { engine, code } = ctx.request.body;
        console.log('Selected engine: ', engine);
        console.log('Code to be parsed: ', code);

        let parsedData = null;

        const startTime = new Date().getTime();
        console.log('Parsing start time: ', startTime);

        try {
            if (engine === 'acorn') {
                const MyParser = Parser.extend(acornJsx, acornBigint);
                parsedData = MyParser.parse(code);  
            } else if (engine === 'esprima') {
                parsedData = esprima.parseScript(code); 
            } else {
                ctx.body = { code: 400, message: "Invalid engine specified" };
                return;  
            }
        } catch (error) {
            ctx.body = { code: 500, message: "Error during parsing", error: error.message };
            return; 
        }

        const endTime = new Date().getTime();
        console.log('Parsing end time: ', endTime);
        const elapsedTime = endTime - startTime;
        console.log('Parsing consume time: ', elapsedTime);
        
        // 返回包含解析结果和耗时的响应
        ctx.body = {
            code: 200,
            time: elapsedTime,       
            data: parsedData         
        };
    }
}

module.exports = new Codeparse();