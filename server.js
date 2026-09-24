// Life Chat Server - Real-time secure chat for Life MTL - FIXED FOR ITCH.IO v2
import express from 'express';
import http from 'http';
import { WebSocketServer } from 'ws';
import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import fs from 'fs';
import cors from 'cors';

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'life-super-secret-change-me-in-prod';
const MOD = JSON.parse(fs.readFileSync('./moderation.json','utf8'));

const app = express();
app.use(cors({origin:'*'}));
app.use(express.json());

const clients = new Map();
const pseudoToWs = new Map();
const rooms = new Map();
const messageHistory = new Map();

function getOrCreateRoom(name){
  if(!rooms.has(name)) rooms.set(name, new Set());
  if(!messageHistory.has(name)) messageHistory.set(name, []);
  return rooms.get(name);
}
getOrCreateRoom('general');

function isValidPseudo(p){ return /^[a-zA-Z0-9_\-]{3,16}$/.test(p); }

function filterText(text){
  let t = text.trim().slice(0, MOD.spam.max_length);
  let lower = t.toLowerCase();
  let flagged = false;
  for(const w of MOD.banned_words){
    if(lower.includes(w.toLowerCase())){
      flagged = true;
      const re = new RegExp(w.replace(/[.*+?^${}()|[\]\\]/g,'\\$&'), 'gi');
      t = t.replace(re, MOD.replace_char.repeat(w.length));
    }
  }
  if(t.length>6){
    const caps = (t.match(/[A-Z]/g)||[]).length / t.length;
    if(caps > MOD.spam.caps_ratio) t = t.toLowerCase();
  }
  return {text:t, flagged};
}

app.post('/auth', (req,res)=>{
  let {pseudo} = req.body;
  if(!pseudo || !isValidPseudo(pseudo)) return res.status(400).json({error:'Pseudo invalide: 3-16 caracteres alphanumeriques _-'});
  let finalPseudo = pseudo;
  let tries=0;
  while(pseudoToWs.has(finalPseudo.toLowerCase()) && tries<30){
    tries++;
    finalPseudo = pseudo.slice(0,10) + Math.floor(Math.random()*900+100);
  }
  if(pseudoToWs.has(finalPseudo.toLowerCase())){
    return res.status(409).json({error:'Trop de monde avec ce pseudo, reessaie'});
  }
  const id = uuidv4();
  const token = jwt.sign({id, pseudo: finalPseudo}, JWT_SECRET, {expiresIn:'7d'});
  console.log(`[AUTH] ${pseudo} -> ${finalPseudo} (${id})`);
  res.json({id, uid:id, pseudo:finalPseudo, token});
});

app.get('/health', (_,res)=>res.json({ok:true, players: clients.size, rooms: [...rooms.keys()]}));
app.get('/', (_,res)=>res.send('Life Chat Server OK - FIXED FOR ITCH.IO v2'));

const server = http.createServer(app);
const wss = new WebSocketServer({ server, path:'/ws' });

function broadcastToRoom(room, payload, exceptWs=null){
  const set = rooms.get(room);
  if(!set) return;
  const data = JSON.stringify(payload);
  for(const ws of set){
    if(ws===exceptWs) continue;
    if(ws.readyState!==1) continue;
    const meta = clients.get(ws);
    if(payload.fromPseudo && meta?.blocked?.has(payload.fromPseudo.toLowerCase())) continue;
    try{ ws.send(data); }catch{}
  }
}

function sendPresence(room){
  const set = rooms.get(room);
  if(!set) return;
  const list = [...set].map(ws=>{
    const m=clients.get(ws);
    return m? {id:m.id, uid:m.id, pseudo:m.pseudo, user:{pseudo:m.pseudo, uid:m.id}} : null;
  }).filter(Boolean);
  broadcastToRoom(room, {type:'presence', room, players:list, users:list, count:list.length});
}

wss.on('connection', (ws)=>{
  let authed=false;
  let authTimeout = setTimeout(()=>{ if(!authed) ws.close(4001,'auth timeout'); }, 5000);
  ws.on('message', raw=>{
    let msg;
    try{ msg=JSON.parse(raw.toString()); }catch{ return ws.send(JSON.stringify({type:'error', error:'JSON invalide'})); }
    if(msg.type==='auth'){
      try{
        const decoded = jwt.verify(msg.token, JWT_SECRET);
        const {id, pseudo} = decoded;
        const lower = pseudo.toLowerCase();
        if(pseudoToWs.has(lower) && pseudoToWs.get(lower)!==ws){
          return ws.send(JSON.stringify({type:'error', error:'Pseudo deja connecte'}));
        }
        clearTimeout(authTimeout);
        authed=true;
        const room = msg.room && typeof msg.room==='string' ? msg.room.slice(0,20) : 'general';
        clients.set(ws, {id, pseudo, room, mutedUntil:0, lastMessages:[], lastMsgTime:0, infractions:0, blocked:new Set()});
        pseudoToWs.set(lower, ws);
        getOrCreateRoom(room).add(ws);
        console.log(`+ ${pseudo} -> ${room} (${clients.size})`);
        ws.send(JSON.stringify({type:'authed', id, uid:id, pseudo, room}));
        const hist = messageHistory.get(room) || [];
        ws.send(JSON.stringify({type:'history', room, messages: hist.slice(-50)}));
        const histOld = hist.slice(-50).map(m=>({id:m.id, uid:m.from||m.uid||m.id, pseudo:m.fromPseudo||m.pseudo, user:m.fromPseudo||m.pseudo, text:m.text, time:m.ts||m.time||Date.now()}));
        ws.send(JSON.stringify({type:'room_joined', room, history: histOld}));
        broadcastToRoom(room, {type:'join', pseudo, id, uid:id, ts:Date.now(), time:Date.now()}, ws);
        broadcastToRoom(room, {type:'player_joined', user:{pseudo, uid:id}, pseudo, id, uid:id}, ws);
        sendPresence(room);
      }catch(e){
        ws.send(JSON.stringify({type:'error', error:'Token invalide'}));
        ws.close(4002,'bad token');
      }
      return;
    }
    if(!authed) return;
    const meta = clients.get(ws);
    if(!meta) return;
    if(Date.now() < meta.mutedUntil){
      return ws.send(JSON.stringify({type:'error', error:`Mute jusqu'a ${new Date(meta.mutedUntil).toLocaleTimeString()}`, muteUntil: meta.mutedUntil}));
    }
    switch(msg.type){
      case 'join': {
        const newRoom = (msg.room||'general').slice(0,20).toLowerCase();
        if(newRoom===meta.room) break;
        rooms.get(meta.room)?.delete(ws);
        broadcastToRoom(meta.room, {type:'leave', pseudo:meta.pseudo, id:meta.id, uid:meta.id, ts:Date.now(), time:Date.now()});
        broadcastToRoom(meta.room, {type:'player_left', pseudo:meta.pseudo, id:meta.id, uid:meta.id});
        sendPresence(meta.room);
        meta.room=newRoom;
        getOrCreateRoom(newRoom).add(ws);
        const hist = messageHistory.get(newRoom)||[];
        ws.send(JSON.stringify({type:'joined', room:newRoom, messages:hist.slice(-50)}));
        ws.send(JSON.stringify({type:'room_joined', room:newRoom, history: hist.slice(-50).map(m=>({id:m.id, uid:m.from||m.uid||m.id, pseudo:m.fromPseudo||m.pseudo, user:m.fromPseudo||m.pseudo, text:m.text, time:m.ts||m.time}))}));
        broadcastToRoom(newRoom, {type:'join', pseudo:meta.pseudo, id:meta.id, uid:meta.id, ts:Date.now(), time:Date.now()}, ws);
        broadcastToRoom(newRoom, {type:'player_joined', user:{pseudo:meta.pseudo, uid:meta.id}, pseudo:meta.pseudo, id:meta.id, uid:meta.id}, ws);
        sendPresence(newRoom);
        break;
      }
      case 'message': {
        let text = (msg.text||'').toString();
        if(!text.trim()) break;
        const now=Date.now();
        if(now - meta.lastMsgTime < MOD.spam.min_interval_ms){
          return ws.send(JSON.stringify({type:'error', error:'Trop rapide, attends un peu'}));
        }
        const recent = meta.lastMessages.filter(t=> now - t.ts < 10000);
        if(recent.length >= MOD.spam.max_messages_per_10s){
          meta.infractions++;
          if(meta.infractions>=3){ meta.mutedUntil = now + 60000; meta.infractions=0; return ws.send(JSON.stringify({type:'muted', duration:60000, reason:'Spam'})); }
          return ws.send(JSON.stringify({type:'error', error:'Spam detecte, ralentis'}));
        }
        if(meta.lastMessages.slice(-MOD.spam.duplicate_window).some(m=> m.text===text)){
          return ws.send(JSON.stringify({type:'error', error:'Message duplique'}));
        }
        const {text:filtered, flagged} = filterText(text);
        if(flagged) meta.infractions++;
        meta.lastMsgTime = now;
        meta.lastMessages.push({text, ts:now});
        if(meta.lastMessages.length>20) meta.lastMessages.shift();
        if(meta.infractions>=5){ meta.mutedUntil = now + 5*60000; meta.infractions=0; broadcastToRoom(meta.room, {type:'muted', pseudo:meta.pseudo, duration:5*60000}); }
        const packet = {type:'message', id: uuidv4(), uid: meta.id, from: meta.id, fromPseudo: meta.pseudo, pseudo: meta.pseudo, user: meta.pseudo, text: filtered, time: now, ts: now, room: meta.room, filtered: flagged};
        const hist = messageHistory.get(meta.room);
        hist.push(packet);
        if(hist.length>200) hist.shift();
        broadcastToRoom(meta.room, packet);
        break;
      }
      case 'block': {
        const target = (msg.pseudo||'').toLowerCase();
        if(target) meta.blocked.add(target);
        ws.send(JSON.stringify({type:'blocked', pseudo:msg.pseudo}));
        break;
      }
      case 'unblock': {
        const target = (msg.pseudo||'').toLowerCase();
        meta.blocked.delete(target);
        ws.send(JSON.stringify({type:'unblocked', pseudo:msg.pseudo}));
        break;
      }
      case 'report': {
        console.log(`[REPORT] ${meta.pseudo} report ${msg.targetPseudo}: ${msg.reason}`);
        ws.send(JSON.stringify({type:'report_ok'}));
        break;
      }
      case 'ping': {
        ws.send(JSON.stringify({type:'pong', ts:Date.now()}));
        break;
      }
    }
  });

  ws.on('close', ()=>{
    clearTimeout(authTimeout);
    const meta = clients.get(ws);
    if(meta){
      pseudoToWs.delete(meta.pseudo.toLowerCase());
      rooms.get(meta.room)?.delete(ws);
      broadcastToRoom(meta.room, {type:'leave', pseudo:meta.pseudo, id:meta.id, uid:meta.id, ts:Date.now(), time:Date.now()});
      broadcastToRoom(meta.room, {type:'player_left', pseudo:meta.pseudo, id:meta.id, uid:meta.id});
      sendPresence(meta.room);
      clients.delete(ws);
      console.log(`- ${meta.pseudo} (${clients.size})`);
    }
  });
  ws.on('error', ()=>{});
});

server.listen(PORT, ()=>console.log(`Life Chat Server FIXED v2 listening on ${PORT} - READY FOR ITCH.IO`));
