const http = require('http');
const net = require('net');
const crypto = require('crypto');

const PORT = process.env.PORT || 8080;
const RAW_UUID = process.env.UUID || 'd342d11e-d424-4583-b36e-524ab1f0afa4';
const UUID = RAW_UUID.replace(/-/g, '').toLowerCase();
const WSPATH = process.env.WSPATH || '/vless';

function encodeWsFrame(data) {
  const len = data.length;
  let header;
  if (len < 126) {
    header = Buffer.from([0x82, len]);
  } else if (len < 65536) {
    header = Buffer.alloc(4);
    header[0] = 0x82;
    header[1] = 126;
    header.writeUInt16BE(len, 2);
  } else {
    header = Buffer.alloc(10);
    header[0] = 0x82;
    header[1] = 127;
    header.writeBigUInt64BE(BigInt(len), 2);
  }
  return Buffer.concat([header, data]);
}

const server = http.createServer((req, res) => {
  if (req.url === '/sub') {
    const host = req.headers.host || 'your-domain.com';
    const vless = `vless://${RAW_UUID}@${host}:443?encryption=none&security=tls&sni=${host}&fp=chrome&type=ws&host=${host}&path=${encodeURIComponent(WSPATH)}#Wasmer-VLESS`;
    res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
    return res.end(vless + '\n');
  }
  res.writeHead(200, { 'Content-Type': 'text/plain' });
  res.end('Wasmer Edge Service Running\n');
});

server.on('upgrade', (req, socket) => {
  if (!req.url.startsWith(WSPATH)) return socket.destroy();
  const key = req.headers['sec-websocket-key'];
  if (!key) return socket.destroy();

  const accept = crypto
    .createHash('sha1')
    .update(key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11')
    .digest('base64');

  socket.write(
    'HTTP/1.1 101 Switching Protocols\r\n' +
    'Upgrade: websocket\r\n' +
    'Connection: Upgrade\r\n' +
    `Sec-WebSocket-Accept: ${accept}\r\n\r\n`
  );

  let remote = null;
  let vlessHeaderParsed = false;
  let buffer = Buffer.alloc(0);

  socket.on('data', (chunk) => {
    buffer = Buffer.concat([buffer, chunk]);

    while (buffer.length >= 2) {
      const secondByte = buffer[1];
      const isMasked = (secondByte & 0x80) !== 0;
      let payloadLen = secondByte & 0x7f;
      let offset = 2;

      if (payloadLen === 126) {
        if (buffer.length < 4) return;
        payloadLen = buffer.readUInt16BE(2);
        offset = 4;
      } else if (payloadLen === 127) {
        if (buffer.length < 10) return;
        payloadLen = Number(buffer.readBigUInt64BE(2));
        offset = 10;
      }

      const maskOffset = offset;
      if (isMasked) offset += 4;
      if (buffer.length < offset + payloadLen) return;

      const payload = Buffer.alloc(payloadLen);
      for (let i = 0; i < payloadLen; i++) {
        payload[i] = isMasked ? buffer[offset + i] ^ buffer[maskOffset + (i % 4)] : buffer[offset + i];
      }
      buffer = buffer.subarray(offset + payloadLen);

      if (!vlessHeaderParsed) {
        vlessHeaderParsed = true;
        if (payload.length < 24) return socket.destroy();

        const version = payload[0];
        const clientUuid = payload.subarray(1, 17).toString('hex').toLowerCase();
        if (clientUuid !== UUID) return socket.destroy();

        const addonLen = payload[17];
        let pOffset = 18 + addonLen;
        const cmd = payload[pOffset++];
        if (cmd !== 1) return socket.destroy();

        const targetPort = payload.readUInt16BE(pOffset);
        pOffset += 2;

        const addrType = payload[pOffset++];
        let targetHost = '';
        if (addrType === 1) {
          targetHost = Array.from(payload.subarray(pOffset, pOffset + 4)).join('.');
          pOffset += 4;
        } else if (addrType === 2) {
          const dLen = payload[pOffset++];
          targetHost = payload.subarray(pOffset, pOffset + dLen).toString('utf8');
          pOffset += dLen;
        } else {
          return socket.destroy();
        }

        const initialData = payload.subarray(pOffset);
        socket.write(encodeWsFrame(Buffer.from([version, 0])));

        remote = net.connect({ host: targetHost, port: targetPort }, () => {
          if (initialData.length > 0) remote.write(initialData);
        });

        remote.on('data', (d) => {
          if (!socket.destroyed) socket.write(encodeWsFrame(d));
        });
        remote.on('error', () => socket.destroy());
        remote.on('close', () => socket.destroy());
      } else if (remote && !remote.destroyed) {
        remote.write(payload);
      }
    }
  });

  socket.on('error', () => { if (remote) remote.destroy(); });
  socket.on('close', () => { if (remote) remote.destroy(); });
});

server.listen(PORT, '127.0.0.1', () => {
  console.log(`Server listening on port ${PORT}`);
});
