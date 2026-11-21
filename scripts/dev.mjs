import http from 'node:http';
import {readFile} from 'node:fs/promises';
import path from 'node:path';
const args=process.argv.slice(2),port=Number(args[args.indexOf('--port')+1])||8000;
const root=process.cwd();
http.createServer(async(req,res)=>{try{const url=new URL(req.url,'http://localhost');let filename=decodeURIComponent(url.pathname);if(filename.endsWith('/'))filename+='index.html';const target=path.resolve(root,'.'+filename);if(!target.startsWith(root+path.sep)||filename.split('/').some(p=>p.startsWith('.'))){res.writeHead(403).end();return;}const data=await readFile(target);res.writeHead(200,{'Content-Type':({'.html':'text/html; charset=utf-8','.js':'text/javascript; charset=utf-8','.css':'text/css; charset=utf-8','.json':'application/json'})[path.extname(target)]||'application/octet-stream'});res.end(data);}catch{res.writeHead(404).end('Not found');}}).listen(port,'0.0.0.0',()=>console.log(`Preview on port ${port}`));
