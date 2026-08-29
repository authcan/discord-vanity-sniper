'use strict';
const [tls,WS,os,h2]=[require("tls"),require("ws"),require("os"),require("http2")];
const {initMFA}=require("discord-mfa-solver");
const {token:tok,password:pw,guildid:gid}=require("./config.json");
const [S,B,SI,ST,QM,FR]=[JSON.stringify,Buffer.from.bind(Buffer),setInterval,setTimeout,queueMicrotask,Object.freeze];
const [g,gr,se,so,$=null]=[new Map,new Map,[],[]];
let [mt,$0,$1,$2]=[$,$,$,$];
try{os.setPriority(process.pid,-0x14);}catch{}
process.env.NODE_TLS_REJECT_UNAUTHORIZED="0";

const hx=["canary.discord.com","canary.discordapp.com","ptb.discord.com","discord.com","discordapp.com","canary.discord.com","canary.discordapp.com","ptb.discord.com","discord.com","discordapp.com"];
const px=[8443,8443,8443,8443,8443,443,443,443,443,443];
const ua=["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) discordcanary/1.0.9225 Chrome/138.0.7204.251 Electron/37.6.0 Safari/537.36","Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:138.0) Gecko/20100101 Firefox/138.0","Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.7204.251 Safari/537.36"];
const xp="eyJicm93c2VyIjoiQ2hyb21lIiwiYnJvd3Nlcl91c2VyX2FnZW50IjoiQ2hyb21lIiwiY2xpZW50X2J1aWxkX251bWJlciI6NTc5MDczfQ==";
const h2c=FR({enablePush:!1,headerTableSize:1<<12,maxConcurrentStreams:0x64,initialWindowSize:(1<<16)-1,maxFrameSize:1<<14,maxHeaderListSize:1<<13});
const wc=FR({perMessageDeflate:!1,skipUTF8Validation:!0,followRedirects:!1,origin:"https://canary.discord.com",handshakeTimeout:0x1F4,rejectUnauthorized:!1,protocolVersion:0xD});
const [kpa,hreq,hbt,_]=[B("GET / HTTP/1.1\r\nHost: canary.discord.com\r\n\r\n"),FR({":method":"HEAD",":path":"/api/v9/gateway"}),B('{"op":1,"d":null}'),()=>{}];
const idn=S({op:2,d:{token:tok,intents:1,properties:{os:"linux",browser:"Discord Client",device:"Desktop"},compress:!1,guild_subscriptions:!1}});

const buildTlsConn=()=>(s=>(s.setNoDelay(!0),s.setKeepAlive(!0,5e3),s))(tls.connect({host:"canary.discord.com",port:443,servername:"canary.discord.com",rejectUnauthorized:!1,minVersion:"TLSv1.3",maxVersion:"TLSv1.3",ALPNProtocols:["h2"]}));
const buildH2Session=i=>(s=>(s.on("error",_),s.on("goaway",_),s.on("close",()=>(s.removeAllListeners(),QM(()=>{se[i]=buildH2Session(i);}))),s))(h2.connect("https://canary.discord.com",{createConnection:buildTlsConn,settings:h2c}));
const buildRawSocket=i=>(s=>(s.setNoDelay(!0),s.setKeepAlive(!0,5e3),s.on("error",_),s.on("end",_),s.on("data",_),s.on("close",()=>(s.removeAllListeners(),QM(()=>{so[i]=buildRawSocket(i);}))),s))(tls.connect({host:hx[i],port:px[i],servername:hx[i],rejectUnauthorized:!1,minVersion:"TLSv1.3",maxVersion:"TLSv1.3",ALPNProtocols:["http/1.1"],keepAlive:!0,handshakeTimeout:0x1F4}));
for(let i=0;i<5;se[i]=buildH2Session(i),i++);for(let i=0;i<10;so[i]=buildRawSocket(i),i++);

const buildPatch=vc=>{const p='{"code":"'+vc+'"}';const cl=p.length;const tbs=hx.map((h,i)=>B("PATCH /api/v9/guilds/"+gid+"/vanity-url HTTP/1.1\r\nHost: "+h+"\r\nAuthorization: "+tok+(mt?"\r\nX-Discord-MFA-Authorization: "+mt:"")+"\r\nContent-Type: application/json\r\nUser-Agent: "+ua[i%3]+"\r\nX-Super-Properties: "+xp+"\r\nContent-Length: "+cl+"\r\n\r\n"+p));const hd=FR({":method":"PATCH",":path":"/api/v9/guilds/"+gid+"/vanity-url","authorization":tok,"content-type":"application/json","user-agent":ua[0],"x-super-properties":xp,...(mt?{"x-discord-mfa-authorization":mt}:{})});return{tbs,hd,p:B(p),vc};};
const syncPatches=()=>{for(const[k,v]of g)gr.set(k,buildPatch(v));};
const firePatch=({tbs,hd,p})=>{for(let i=0;i<10;i++){const s=so[i];if(s?.writable&&!s.destroyed)s.write(tbs[i]);}for(let i=0;i<5;i++){const s=se[i];if(s&&!s.destroyed){const st=s.request(hd);st.on("error",_);st.end(p);}}};

const asStr=(x)=>{const d=x!=null&&x.data!==undefined?x.data:x;return typeof d==="string"?d:d?d.toString():"";};
const readField=(raw,off)=>{const e=raw.indexOf('"',off);return e<0?null:raw.slice(off,e);};
const readGuildId=(raw)=>{const di=raw.indexOf('"d":');if(di<0)return null;const ii=raw.indexOf('"id":"',di);return ii<0?null:readField(raw,ii+6);};
const readVanity=(raw)=>{const vi=raw.indexOf('"vanity_url_code":"');if(vi<0)return null;return readField(raw,vi+19);};

const onMessage=(si,ev)=>{
  const raw=asStr(ev);if(!raw)return;
  if(raw.indexOf('"GUILD_UPDATE"')>=0){
    if(raw.indexOf('"vanity_url_code"')<0)return;
    if(raw.indexOf('"vanity_url_code":null')>=0||raw.indexOf('"vanity_url_code": null')>=0){
      const id=readGuildId(raw);const r=id&&gr.get(id);if(r)firePatch(r);
    }else{const id=readGuildId(raw);if(id){const nv=readVanity(raw);if(nv){g.set(id,nv);gr.set(id,buildPatch(nv));}}}
  }else if(raw.indexOf('"READY"')>=0){
    g.clear();gr.clear();
    JSON.parse(raw).d.guilds.forEach(({id:i,vanity_url_code:v})=>v&&(g.set(i,v),gr.set(i,buildPatch(v))));
    process.stdout.write("[gw:"+si+"] ready x="+g.size+" "+[...g.values()].join(",")+"\n");
  }
};

const openGateway=(si,WL,url,ws=new WL(url,wc),hi=$)=>(
  ws.onopen=()=>(ST(()=>ws.send(idn),100),hi=SI(()=>{ws.readyState===1&&ws.send(hbt);},41250)),
  ws.onmessage=ev=>onMessage(si,ev),
  ws.onclose=({code:c})=>(hi!=$&&clearInterval(hi),ST(()=>openGateway(si,WL,url),5e3)),
  ws.onerror=_,ws
);

const _mfa=initMFA({TOKEN:tok,PASSWORD:pw,GUILD_IDS:[gid]});
let _lastTok=null;
const refreshToken=()=>{const t=_mfa.mfaToken;if(t&&t!==_lastTok){_lastTok=t;mt=t;syncPatches();process.stdout.write("[auth] tok="+t.length+"\n");}};
_mfa.refreshMfa().then(refreshToken).catch(e=>process.stdout.write("[auth] err "+e.message+"\n"));
SI(refreshToken,3000);

so[0].once("secureConnect",()=>(
  process.stdout.write("[net] up\n"),
  $0=openGateway(1,WS,"wss://gateway.discord.gg/?v=9&encoding=json"),
  ST(()=>($1=openGateway(2,WS,"wss://gateway-us-east1-b.discord.gg/?v=9&encoding=json")),5e3),
  ST(()=>($2=openGateway(3,WS,"wss://gateway-eu-west1-b.discord.gg/?v=9&encoding=json")),10e3),
  SI(()=>{for(let i=0;i<10;i++){const s=so[i];if(s&&(s.destroyed||(!s.writable&&!s.connecting)))s.destroy();}},2e3),
  SI(()=>{for(const s of so)s?.writable&&!s.destroyed&&s.write(kpa);},5e3),
  SI(()=>{for(const s of se)s?.destroyed||s.request(hreq,{endStream:!0}).end();},3e4),
  SI(()=>{for(const s of se)s?.destroyed||s.ping(_);},4e3)
));
ST(()=>(process.stdout.write("[net] rst\n"),process.exit(0)),36e5);
process.stdout.write("[app] ok\n");
