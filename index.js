const http = require('http');
const crypto = require('crypto');
const fetch = require('node-fetch');

const ADDRESS = "https://alist.xzpan.tk";
const TOKEN = "alist-6fd33570-60be-4737-bb31-bfa41f6dfb52Ej3buinXtVXHlm7cuYYYeZpP91Mx1gx3jSUd356e2T8ki2rbwWi6p6WJI5VgTAnp";

async function verify(data, _sign) {
  const signSlice = _sign.split(":");
  if (!signSlice[signSlice.length - 1]) {
    return "expire missing";
  }
  const expire = parseInt(signSlice[signSlice.length - 1]);
  if (isNaN(expire)) {
    return "expire invalid";
  }
  if (expire < Date.now() / 1e3 && expire > 0) {
    return "expire expired";
  }
  const right = await hmacSha256Sign(data, expire);
  if (_sign !== right) {
    return "sign mismatch";
  }
  return "";
}

async function hmacSha256Sign(data, expire) {
  const key = crypto.createHmac('sha256', Buffer.from(TOKEN));
  const buf = key.update(`${data}:${expire}`).digest();
  const base64 = Buffer.from(buf).toString('base64');
  return base64.replace(/\+/g, "-").replace(/\//g, "_") + ":" + expire;
}

const server = http.createServer(async (req, res) => {
  const origin = req.headers.origin || "*";
  const url = new URL(req.url, `http://${req.headers.host}`);
  const path = decodeURIComponent(url.pathname);
  const sign = url.searchParams.get("sign") || "";

  if (req.method === "OPTIONS") {
    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET,HEAD,POST,OPTIONS",
      "Access-Control-Max-Age": "86400"
    };
    let headers = req.headers;
    if (headers.get("Origin") !== null && headers.get("Access-Control-Request-Method") !== null) {
      let respHeaders = {
        ...corsHeaders,
        "Access-Control-Allow-Headers": headers.get("Access-Control-Request-Headers") || ""
      };
      res.writeHead(200, respHeaders);
      res.end();
    } else {
      res.writeHead(200, { Allow: "GET, HEAD, POST, OPTIONS" });
      res.end();
    }
  } else {
    const verifyResult = await verify(path, sign);
    if (verifyResult !== "") {
      res.writeHead(401, { "content-type": "application/json;charset=UTF-8", "Access-Control-Allow-Origin": origin });
      res.end(JSON.stringify({ code: 401, message: verifyResult }));
      return;
    }

    let fetchRes = await fetch(`${ADDRESS}/api/fs/link`, {
      method: "POST",
      headers: {
        "content-type": "application/json;charset=UTF-8",
        Authorization: TOKEN
      },
      body: JSON.stringify({
        path
      })
    });

    let fetchJson = await fetchRes.json();
    if (fetchJson.code !== 200) {
      res.writeHead(fetchJson.code, { "content-type": "application/json;charset=UTF-8" });
      res.end(JSON.stringify(fetchJson));
      return;
    }

    let fetchReq = new fetch.Request(fetchJson.data.url, {
      headers: req.headers,
      redirect: "follow"
    });

    let response = await fetch(fetchReq);

    let responseBody = await response.text();
    let headers = Object.fromEntries(response.headers.entries());

    delete headers['set-cookie'];

    headers["Access-Control-Allow-Origin"] = origin;
    headers["Vary"] = "Origin";

    res.writeHead(response.status, headers);
    res.end(responseBody);
  }
});

const PORT = 3000;

server.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});
