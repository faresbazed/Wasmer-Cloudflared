const http = require('http');
const net = require('net');
const { WebSocketServer, createWebSocketStream } = require('ws');

const PORT = process.env.PORT || 8080;
const UUID = (process.env.UUID || 'd342d11e-d424-4583-b36e-524ab1f0afa4').replace(/-/g, '');
const WSPATH = process.env.WSPATH || '/vless';

const server = http.createServer((req, res) => {
  if (req.url === '/sub') {
    const host = req.headers.host || 'your-domain.com';
    const rawUuid = process.env.UUID || 'd342d11e-d424-4583-b36e-524ab1f0afa4';
    const vlessUri = `vless://${rawUuid}@${host}:443?encryption=none&security=tls&sni=${host}&fp=chrome&type=ws&host=${host}&path=${encodeURIComponent(WSPATH)}#Wasmer-VLESS`;
    res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
    return res.end(vlessUri + '\n');
  }
  res.writeHead(200, { 'Content-Type': 'text/plain' });
  res.end('Wasmer Edge Service Running\n');
});

const wss = new WebSocketServer({ noServer: true });

server.on('upgrade', (request, socket, head) => {
  if (request.url.startsWith(WSPATH)) {
    wss.handleUpgrade(request, socket, head, (ws) => {
      wss.emit('connection', ws, request);
    });
  } else {
    socket.destroy();
  }
});

wss.on('connection', (ws) => {
  ws.once('message', (msg) => {
    const buf = Buffer.from(msg);
    if (buf.length < 24) return ws.close();

    const version = buf[0];
    const clientUuid = buf.subarray(1, 17).toString('hex');
    if (clientUuid !== UUID) return ws.close();

    const addonLen = buf[17];
    let offset = 18 + addonLen;
    const cmd = buf[offset++]; // 1 = TCP
    if (cmd !== 1) return ws.close();

    const targetPort = buf.readUInt16BE(offset);
    offset += 2;

    const addrType = buf[offset++];
    let targetHost = '';

    if (addrType === 1) { // IPv4
      targetHost = Array.from(buf.subarray(offset, offset + 4)).join('.');
      offset += 4;
    } else if (addrType === 2) { // Domain
      const domainLen = buf[offset++];
      targetHost = buf.subarray(offset, offset + domainLen).toString('utf8');
      offset += domainLen;
    } else if (addrType === 3) { // IPv6
      const parts = [];
      for (let i = 0; i < 8; i++) {
        parts.push(buf.readUInt16BE(offset + i * 2).toString(16));
      }
      targetHost = parts.join(':');
      offset += 16;
    } else {
      return ws.close();
    }

    const initialPayload = buf.subarray(offset);

    // Send VLESS response header [version, 0x00]
    ws.send(Buffer.from([version, 0]));

    const duplex = createWebSocketStream(ws);
    const remote = net.connect({ host: targetHost, port: targetPort }, () => {
      if (initialPayload.length > 0) {
        remote.write(initialPayload);
      }
      duplex.pipe(remote).on('error', () => {});
      remote.pipe(duplex).on('error', () => {});
    });

    remote.on('error', () => ws.close());
    duplex.on('error', () => remote.destroy());
  });
});

server.listen(PORT, '127.0.0.1', () => {
  console.log(`VLESS WS Server listening on port ${PORT}`);
});
