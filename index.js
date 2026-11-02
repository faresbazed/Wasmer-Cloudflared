const http = require('http');

const port = process.env.PORT || 8080;
const host = '127.0.0.1';

const server = http.createServer((req, res) => {
  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({
    status: 'online',
    message: 'Running natively on Wasmer Edge (wasi/wasm32) without cloudflared!',
    path: req.url
  }));
});

server.listen(port, host, () => {
  console.log(`Server listening on http://${host}:${port}`);
});
