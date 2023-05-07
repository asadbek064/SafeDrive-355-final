const http = require("http");
const url = require("url");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const querystring = require("querystring");

const {
  access_auth_url,
  access_token_url,
  client_id,
  client_secret,
  scope,
  redirect_uri,
  redirect_uri_code_token,
  hybrid_api_key,
  hybrid_api_url
} = require("./env.json");
var job_states = [];

http
  .createServer(function (req, res) {
    
    var FAVICON = path.join(__dirname, "public", "favicon.ico");
    var INDEX = path.join(__dirname, "public", "index.html");

    // get requested route path
    var pathname = url.parse(req.url).pathname;
    console.log(pathname);

    if (pathname === "/") {
      // serve index.html
      res.writeHead(200, { "Content-Type": "text/html" });
      fs.createReadStream(INDEX).pipe(res);
      return;
    } else if (req.method === "POST" && pathname === "/upload-file") {
      // accept the file and store it in tmp folder
      const state = crypto.randomBytes(3).toString("hex");

      handleFileUpload(req, state, (err, savePath) => {
        if (err) {
          console.log(err);
          res.writeHead(500).end("fail to save file to the server\n");
        }

        // append savePath to be tracked in jobs
        job_states.push({ state, savePath });
        redirect_to_googleauth(state, res);
      });
    } else if (pathname === '/auth/google/callback') {
      // extract code and state from param
      const { code, state } = url.parse(req.url, true).query;
      console.log(code);

      const job_state = job_states.find(job_state => job_state.state === state);

      // return early check
      if (code === undefined || state === undefined || job_state === undefined) {
        res.writeHead(400).end("/auth/google/callback failed undefined val\n");
      }

      send_access_token_request(code, state, res);

      res.writeHead(200).end();
    }else if (pathname === "/favicon.ico") {
      // serve favicon
      res.setHeader("Content-Type", "image/x-icon");
      fs.createReadStream(FAVICON).pipe(res);
      return;
    }
  }).listen(3000);

function redirect_to_googleauth(state, res) {
  const redirectString = `${access_auth_url}?response_type=code&client_id=${client_id}&redirect_uri=${redirect_uri}&scope=${scope}&state=${state}`;
  // Server redirect causes CORS for Google OAuth, so return redirect URL and auto-redirect from client-side JS.
  res.setHeader('Content-Type', 'application/json');
  res.end(JSON.stringify({ redirectUrl: redirectString }));
}

function send_access_token_request(code, state, res) {
  const authorization_code = "authorization_code";
  const post_data = querystring.stringify({client_id, client_secret, code, authorization_code, redirect_uri_code_token});

  let options = {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded"
    }
  }
  http.request(
    access_token_url,
    options,
    (token_stream) => process_stream(token_stream, receive_access_token, state, res)
  ).end(post_data);
}

function process_stream(stream, callback, ...args) {
  let body = "";
  stream.on("data", chunk => body += chunk);
  stream.on("end", () => callback(body, ...args));
}

function receive_access_token(body, state, res) {
  const { access_token } = JSON.parse(body);
  
  console.log(access_token);

  // check file for any malware and upload to google drive 
  validate_file_for_malware(state, access_token, res); 
}

function validate_file_for_malware(state, access_token, res) {
  // upload file to malware and test for any malware if false upload to users google drive
}

function handleFileUpload(req, hash, callback) {
  const chunks = [];

  req.on("data", (chunk) => {
    chunks.push(chunk);
  });

  // stich all chunks
  req.on("end", () => {
    const data = Buffer.concat(chunks);
    const contentType = req.headers["content-type"];

    // Parsing the multipart form data
    const boundary = contentType.split("; ")[1].split("=")[1];

    // split the data into individual parts based on the boundary.
    const parts = data.toString().split(`--${boundary}`);

    for (let i = 1; i < parts.length - 1; i++) {
      const part = parts[i].trim(); // extract current part and remove whitespaces

      // find end of the section by matching patterns. Two empty new lines indicates that 2xCRLF(https://www.w3.org/TR/html401/interact/forms.html#h-17.13.4) <-reference
      const headerEnd = part.indexOf("\r\n\r\n");

      // extract header and content
      const header = part.substring(0, headerEnd);
      const content = part.substring(headerEnd + 4, part.length - 2);
      const filenameMatch = header.match(/filename="([^"]+)"/); // find string that starts with filename=" plus at least 1+ character that is not double quote and mathc it with double quote to make it a pair

      let _filename = "";

      if (filenameMatch) {
        _filename = filenameMatch[1];
      } else {
        // no filename
        _filename = "untitled-" + hash;
      }

      if (filenameMatch) {
        // extract file name type and path
        const fileName = _filename.split(".");
        const extension = fileName[1];
        const name = fileName[0];
        const savePath = `./uploads/${name}-${hash}.${extension}`;

        // save file to disk
        fs.writeFile(savePath, content, (err) => {
          if (err) {
            console.error(err);
            callback(false, err);
          } else {
            callback(null, savePath);
          }
        });
      }
    }
  });
}
