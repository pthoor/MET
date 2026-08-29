// Minimal static file server for the generated fixtures. The report is a file:// -
// capable single-page document, but serving it over http gives the tests a stable
// origin for localStorage (the Accept Risk persistence flow) across reloads.
const http = require('http');
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '.tmp');
const PORT = Number(process.env.MET_HTML_PORT || 4173);

const server = http.createServer((req, res) => {
  const requested = decodeURIComponent((req.url || '/').split('?')[0]);

  // Playwright starts webServer as a plugin task, which runs before globalSetup - so the
  // readiness probe fires before any fixture exists. It must not depend on .tmp content.
  if (requested === '/healthz') {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('ok');
    return;
  }

  const relative = requested === '/' ? '/report.html' : requested;
  const target = path.join(ROOT, path.normalize(relative).replace(/^(\.\.[/\\])+/, ''));

  if (!target.startsWith(ROOT) || !fs.existsSync(target)) {
    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('Not found');
    return;
  }

  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end(fs.readFileSync(target));
});

server.listen(PORT, () => {
  process.stdout.write(`MET fixture server listening on http://127.0.0.1:${PORT}\n`);
});
