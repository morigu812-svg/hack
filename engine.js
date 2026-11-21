export const EDGES=[[0,1],[0,2],[1,3],[2,3],[2,4],[3,5],[4,5]];
export const NODES=[['entry','ENTRY',13,50],['relay','RELAY',37,24],['proxy','PROXY',37,76],['auth','AUTH',63,24],['storage','STORAGE',63,76],['vault','VAULT',87,50]];
export const TOOLS=['cipher','inject','overflow'];
export class Game{
 constructor(difficulty='normal',agents=1,random=Math.random){this.factor={easy:.7,normal:1,hard:1.35}[difficulty]||1;this.nodes=NODES.map((n,i)=>({id:n[0],name:n[1],x:n[2],y:n[3],owned:i===0,scanned:i===0,analyzed:i===0,weak:TOOLS[Math.floor(random()*3)]}));this.energy=100;this.trace=0;this.elapsed=0;this.jobs=Array(agents).fill(null);this.state='ready';this.events=[];this.nextHeartbeat=8;this.alertLevel=0;this.logSerial=0;}
 log(text,type='',channel='SYSTEM'){this.events.push({id:++this.logSerial,time:this.elapsed,text,type,channel});if(this.events.length>200)this.events.shift();}
 address(i){return `10.77.0.${10+i*17}`;}
 operationLog(j,stage){
 const n=this.nodes[j.i],host=this.address(j.i),op=`OP${j.agent+1}`;
 const lines={
 scan:[`接続要求 → ${host} / 応答待ち`,`応答受信 / ${n.name} のサービスを照合中`,`サービス検出 / ${n.name} / 認証ゲートが応答`],
 analyze:[`${n.name} / 応答パターンを収集中`,`認証ハンドシェイクを解析 / 署名を比較中`,`応答パターンの照合完了 / 解析結果を検証中`],
 breach:[`${j.tool.toUpperCase()} モジュールを起動 / ${host}`,`認証ゲートへアクセス / 防御側の監視が反応`,j.tool===n.weak?'セッション検証完了 / 制御権を要求中':'認証署名が不一致 / 防御側が要求を拒否'],
 extract:['VAULT / 機密アーカイブの一覧を取得','転送チャネル確立 / evidence.enc を回収中','転送ブロックを照合 / 整合性を検証中'],
 cool:['中継セッションを切替 / 追跡経路を分散','監視側の照合を遅延 / 接続を整理中','旧セッションを切断 / 追跡シグナルを低減'],
 recover:['ローカルリソースを再配分','待機プロセスを解放 / エネルギーを再充填','リソースの整合性チェック完了']};
 this.log(`${op} / ${lines[j.kind][stage]}`,stage===2&&j.kind==='analyze'?'good':'','NETWORK');
 }

 start(){this.state='running';this.log('仮想端末を起動 / GHOST OS v0.1');this.log('暗号化トンネル確立 / 接続先 10.77.0.10','good','NETWORK');this.log('接続確立。隣接ノードを探索してください。','good');}
 reachable(i){return this.nodes[i]?.owned||EDGES.some(([a,b])=>(a===i&&this.nodes[b].owned)||(b===i&&this.nodes[a].owned));}
 action(kind,i=0,tool='cipher',agent=0){if(this.state!=='running')return 'ミッションを開始してください。';if(agent<0||agent>=this.jobs.length)return '担当が無効です。';if(this.jobs[agent])return 'この担当は作業中です。';const n=this.nodes[i];if(!n)return 'ノードが見つかりません。';if(!['cool','recover'].includes(kind)&&!this.reachable(i))return '隣接ノードへ先に侵入してください。';if(this.jobs.some(j=>j&&j.i===i&&['scan','analyze','breach','extract'].includes(j.kind))&&!['cool','recover'].includes(kind))return '別の担当がこのノードで作業中です。';
 if(kind==='scan'&&n.scanned)return '探索済みです。';if(kind==='analyze'&&(!n.scanned||n.analyzed))return n.analyzed?'解析済みです。':'先に探索してください。';if(kind==='breach'&&(!n.analyzed||n.owned))return n.owned?'侵入済みです。':'先に解析してください。';if(kind==='extract'&&(i!==5||!n.owned))return 'VAULTへ侵入してから回収してください。';
 const spec={scan:[3,8],analyze:[5,12],breach:[7,20],extract:[9,15],cool:[6,8],recover:[5,0]}[kind];if(!spec)return '不明な操作です。';if(this.energy<spec[1])return 'エネルギー不足。回復してください。';this.energy-=spec[1];this.jobs[agent]={kind,i,tool,total:spec[0]*this.factor,left:spec[0]*this.factor,stage:0,agent};this.log(`OP${agent+1} / ${kind.toUpperCase()} ${n.name}`);this.operationLog(this.jobs[agent],0);return null;}
 tick(dt){if(this.state!=='running')return;this.elapsed+=dt;this.trace+=dt*(.12+this.jobs.filter(Boolean).length*.48)*this.factor;this.energy=Math.min(100,this.energy+dt*.65);for(let a=0;a<this.jobs.length;a++){const j=this.jobs[a];if(!j)continue;j.left-=dt;const stage=Math.min(2,Math.floor((1-j.left/j.total)*3));while(j.stage<stage){j.stage++;this.operationLog(j,j.stage);}if(j.left>0)continue;const n=this.nodes[j.i];this.jobs[a]=null;if(j.kind==='scan')n.scanned=true;if(j.kind==='analyze'){n.analyzed=true;this.log(`${n.name} / 脆弱性を特定 / 推奨ツール ${n.weak.toUpperCase()}`,'good','NETWORK');}if(j.kind==='breach'){if(j.tool===n.weak){n.owned=true;this.log(`${n.name} / 侵入成功`,'good');}else{this.trace+=18;this.log(`${n.name} / ツール不一致。追跡 +18%`,'bad');}}if(j.kind==='cool')this.trace=Math.max(0,this.trace-24);if(j.kind==='recover')this.energy=Math.min(100,this.energy+32);if(j.kind==='extract'){this.state='won';this.log('機密データの回収完了。','good');}if(['scan','analyze','cool','recover'].includes(j.kind))this.log(`${j.kind.toUpperCase()} / 完了`,'good');}if(this.trace>=100||this.elapsed>=240){this.state='lost';this.log(this.trace>=100?'追跡完了。接続が遮断されました。':'制限時間を超過しました。','bad');}const level=this.trace>=80?3:this.trace>=50?2:this.trace>=25?1:0;
 if(level>this.alertLevel){const messages=['','異常通信を検知 / 防御側の監視が強化されました','接続元の照合を開始 / 追跡が進行しています','警告：接続元を特定中 / 冷却を推奨'];this.log(messages[level],level>=2?'bad':'warn','DEFENSE');}this.alertLevel=level;
 if(this.state==='running'&&this.elapsed>=this.nextHeartbeat){this.nextHeartbeat=this.elapsed+8;this.log(this.trace>=50?'監視ノードがセッションを照合中 / 接続元を追跡':'監視パケット受信 / トンネル接続を維持',this.trace>=50?'warn':'','DEFENSE');}
 this.trace=Math.min(100,this.trace);}
}
