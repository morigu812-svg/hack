export const EDGES=[[0,1],[0,2],[1,3],[2,3],[2,4],[3,5],[4,5]];
export const NODES=[['entry','ENTRY',13,50],['relay','RELAY',37,24],['proxy','PROXY',37,76],['auth','AUTH',63,24],['storage','STORAGE',63,76],['vault','VAULT',87,50]];
export const TOOLS=['cipher','inject','overflow'];
export class Game{
 constructor(difficulty='normal',agents=1,random=Math.random){this.factor={easy:.7,normal:1,hard:1.35}[difficulty]||1;this.nodes=NODES.map((n,i)=>({id:n[0],name:n[1],x:n[2],y:n[3],owned:i===0,scanned:i===0,analyzed:i===0,weak:TOOLS[Math.floor(random()*3)]}));this.energy=100;this.trace=0;this.elapsed=0;this.jobs=Array(agents).fill(null);this.state='ready';this.events=[];this.streamClock=0;this.packetSerial=0;this.alertLevel=0;this.logSerial=0;}
 log(text,type='',channel='SYSTEM'){this.events.push({id:++this.logSerial,time:this.elapsed,text,type,channel});if(this.events.length>200)this.events.shift();}
 address(i){return `10.77.0.${10+i*17}`;}
 stream(dt){
 this.streamClock+=dt;
 const due=Math.floor((this.streamClock+1e-9)/.2);
 if(!due)return;
 this.streamClock-=due*.2;
 // Keep the terminal lively without replaying minutes of packets after tab suspension.
 const count=Math.min(due,5);
 for(let k=0;k<count;k++){
 const seq=++this.packetSerial,hex=((seq*2654435761)>>>0).toString(16).padStart(8,'0');
 const busy=this.jobs.filter(Boolean),j=busy.length?busy[seq%busy.length]:null;
 const node=j?this.nodes[j.i]:this.nodes.filter(n=>n.owned)[seq%this.nodes.filter(n=>n.owned).length];
 const host=this.address(this.nodes.indexOf(node)),port=[443,22,8080,8443][seq%4];
 const progress=j?Math.min(99,Math.floor((1-j.left/j.total)*100)):0;
 const lines=j?{
 scan:[`SYN → ${host}:${port} seq=0x${hex}`,`RECV ${host} ttl=64 latency=${8+seq%31}ms`,`PROBE service-table / packet=${seq} status=PENDING`,`FINGERPRINT ${node.name} digest=${hex}`],
 analyze:[`DECODE frame=0x${hex} / entropy=${(6+seq%19/10).toFixed(2)}`,`COMPARE signature-block ${seq} / progress=${progress}%`,`BUFFER ${node.name} offset=0x${hex} bytes=4096`,`AUTH handshake sample #${seq} / processing`],
 breach:[`EXEC ${j.tool.toUpperCase()} / frame=0x${hex}`,`SESSION ${host}:${port} / negotiating access`,`PIPE ${node.name} / stage=${progress}% buffer=0x${hex}`,`RECV auth-challenge id=${hex} / evaluating`],
 extract:[`READ evidence.enc / block=${seq} bytes=8192`,`TRANSFER ${host} / progress=${progress}%`,`CHECKSUM block=${seq} hash=${hex} status=OK`,`WRITE archive-buffer offset=0x${hex}`],
 cool:[`ROTATE relay-hop #${seq} / route=${hex}`,`FLUSH virtual-session cache / block=${seq}`,`TUNNEL rebuild / handshake=0x${hex}`,`RELEASE stale-connection ${hex} / status=OK`],
 recover:[`GC buffer=0x${hex} / released=4096B`,`ALLOC resource-pool / batch=${seq}`,`CHECK local-worker #${seq%8} / status=OK`,`SYNC energy-buffer / progress=${progress}%`]
 }[j.kind]:[`KEEPALIVE ${host}:443 seq=${seq} ack=OK`,`RECV tunnel-frame id=0x${hex} bytes=${128+seq%8*64}`,`ROUTE ${host} / virtual-hop=${1+seq%4} latency=${9+seq%27}ms`,`SESSION ghost@${node.name.toLowerCase()} / channel=OPEN`];
 const defense=seq%13===0;
 this.log(defense?(this.trace>=50?`IDS source-correlation / confidence=${Math.floor(this.trace)}% packet=${hex}`:`FIREWALL packet=${hex} / inspection=PENDING`):lines[seq%lines.length],defense?'warn':seq%7===0?'good':'',defense?'DEFENSE':'NETWORK');
 this.events[this.events.length-1].time=this.elapsed-this.streamClock-(count-1-k)*.2;
 }
 }
 operationLog(j,stage){
 const n=this.nodes[j.i],host=this.address(j.i),op=`OP${j.agent+1}`;
 const lines={
 scan:[`CONNECT ${host} / awaiting response`,`RECV ${n.name} / matching service fingerprint`,`SERVICE ${n.name} / authentication gateway detected`],
 analyze:[`${n.name} / collecting response samples`,`AUTH / comparing handshake signatures`,`MATCH / validating analysis results`],
 breach:[`LOAD ${j.tool.toUpperCase()} / target=${host}`,`AUTH / requesting session access`,j.tool===n.weak?'SESSION / validation passed, requesting control':'DENIED / signature mismatch, request rejected'],
 extract:['VAULT / indexing classified archives','TRANSFER / streaming evidence.enc','VERIFY / checking transfer integrity'],
 cool:['RELAY / rotating virtual session route','ROUTE / rebuilding tunnel chain','CLOSE / releasing previous session'],
 recover:['ALLOC / redistributing local resources','RECOVER / releasing idle process buffers','CHECK / resource integrity verified']};
 this.log(`${op} / ${lines[j.kind][stage]}`,stage===2&&j.kind==='analyze'?'good':'','NETWORK');
 }

 start(){this.state='running';this.log('BOOT / GHOST OS v0.1 initialized');this.log('TUNNEL / encrypted link established → 10.77.0.10','good','NETWORK');this.log('READY / select an adjacent node to begin','good');}
 reachable(i){return this.nodes[i]?.owned||EDGES.some(([a,b])=>(a===i&&this.nodes[b].owned)||(b===i&&this.nodes[a].owned));}
 action(kind,i=0,tool='cipher',agent=0){if(this.state!=='running')return 'ミッションを開始してください。';if(agent<0||agent>=this.jobs.length)return '担当が無効です。';if(this.jobs[agent])return 'この担当は作業中です。';const n=this.nodes[i];if(!n)return 'ノードが見つかりません。';if(!['cool','recover'].includes(kind)&&!this.reachable(i))return '隣接ノードへ先に侵入してください。';if(this.jobs.some(j=>j&&j.i===i&&['scan','analyze','breach','extract'].includes(j.kind))&&!['cool','recover'].includes(kind))return '別の担当がこのノードで作業中です。';
 if(kind==='scan'&&n.scanned)return '探索済みです。';if(kind==='analyze'&&(!n.scanned||n.analyzed))return n.analyzed?'解析済みです。':'先に探索してください。';if(kind==='breach'&&(!n.analyzed||n.owned))return n.owned?'侵入済みです。':'先に解析してください。';if(kind==='extract'&&(i!==5||!n.owned))return 'VAULTへ侵入してから回収してください。';
 const spec={scan:[3,8],analyze:[5,12],breach:[7,20],extract:[9,15],cool:[6,8],recover:[5,0]}[kind];if(!spec)return '不明な操作です。';if(this.energy<spec[1])return 'エネルギー不足。回復してください。';this.energy-=spec[1];this.jobs[agent]={kind,i,tool,total:spec[0]*this.factor,left:spec[0]*this.factor,stage:0,agent};this.log(`OP${agent+1} / ${kind.toUpperCase()} ${n.name}`);this.operationLog(this.jobs[agent],0);return null;}
 tick(dt){if(this.state!=='running')return;this.elapsed+=dt;this.trace+=dt*(.12+this.jobs.filter(Boolean).length*.48)*this.factor;this.energy=Math.min(100,this.energy+dt*.65);for(let a=0;a<this.jobs.length;a++){const j=this.jobs[a];if(!j)continue;j.left-=dt;const stage=Math.min(2,Math.floor((1-j.left/j.total)*3));while(j.stage<stage){j.stage++;this.operationLog(j,j.stage);}if(j.left>0)continue;const n=this.nodes[j.i];this.jobs[a]=null;if(j.kind==='scan')n.scanned=true;if(j.kind==='analyze'){n.analyzed=true;this.log(`${n.name} / SIGNATURE MATCH / recommended module: ${n.weak.toUpperCase()}`,'good','NETWORK');}if(j.kind==='breach'){if(j.tool===n.weak){n.owned=true;this.log(`${n.name} / ACCESS GRANTED / remote control established`,'good');}else{this.trace+=18;this.log(`${n.name} / MODULE MISMATCH / trace +18%`,'bad');}}if(j.kind==='cool')this.trace=Math.max(0,this.trace-24);if(j.kind==='recover')this.energy=Math.min(100,this.energy+32);if(j.kind==='extract'){this.state='won';this.log('MISSION COMPLETE / archive extracted successfully','good');}if(['scan','analyze','cool','recover'].includes(j.kind))this.log(`${j.kind.toUpperCase()} / COMPLETE`,'good');}if(this.trace>=100||this.elapsed>=240){this.state='lost';this.log(this.trace>=100?'TRACE COMPLETE / connection terminated':'TIMEOUT / mission window expired','bad');}const level=this.trace>=80?3:this.trace>=50?2:this.trace>=25?1:0;
 if(level>this.alertLevel){const messages=['','IDS / anomalous traffic detected, monitoring elevated','TRACE / source correlation started','ALERT / source localization imminent, cooling recommended'];this.log(messages[level],level>=2?'bad':'warn','DEFENSE');}this.alertLevel=level;
 if(this.state==='running')this.stream(dt);
 this.trace=Math.min(100,this.trace);}
}
