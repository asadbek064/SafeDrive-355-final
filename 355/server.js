const http = require("http");
const https = require("https");
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
  hybrid_api_key,
  domain
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
    } else if (pathname === "/auth/google/callback") {
      // extract code and state from param
      const { code, state } = url.parse(req.url, true).query;

      const job_state = job_states.find(
        (job_state) => job_state.state === state
      );

      // return early check
      if (
        code === undefined ||
        state === undefined ||
        job_state === undefined
      ) {
        res.writeHead(400).end("/auth/google/callback failed undefined val\n");
      }

      send_access_token_request(code, state, res);

    } else if (pathname === "/favicon.ico") {
      // serve favicon
      res.setHeader("Content-Type", "image/x-icon");
      fs.createReadStream(FAVICON).pipe(res);
      return;
    }
  })
  .listen(3000);

function redirect_to_googleauth(state, res) {
  const redirectString = `${access_auth_url}?response_type=code&client_id=${client_id}&redirect_uri=${redirect_uri}&scope=${scope}&state=${state}`;
  // Server redirect causes CORS for Google OAuth, so return redirect URL and auto-redirect from client-side JS.
  res.setHeader("Content-Type", "application/json");
  res.end(JSON.stringify({ redirectUrl: redirectString }));
}

function send_access_token_request(code, state, res) {
  const authorization_code = "authorization_code";
  const grant_type = "authorization_code";
  const post_data = querystring.stringify({
    client_id,
    client_secret,
    code,
    authorization_code,
    redirect_uri,
    grant_type,
  });

  let options = {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
    },
  };
  https
    .request(access_token_url, options, (token_stream) =>
      process_stream(token_stream, receive_access_token, state, res)
    )
    .end(post_data);
}

function process_stream(stream, callback, ...args) {
  let body = "";
  stream.on("data", (chunk) => (body += chunk));
  stream.on("end", () => callback(body, ...args));
}

function receive_access_token(body, state, res) {
  const { access_token } = JSON.parse(body);

  // check file for any malware and upload to google drive
  scan_file_for_malware(state, access_token, res);

}

// upload file to hybrid-analysis and test for any malware
function scan_file_for_malware(state, access_token, res) {
  const options = {
    method: "POST",
    hostname: "www.hybrid-analysis.com",
    path: "/api/v2/quick-scan/file",
    headers: {
      "User-Agent":
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.82 Safari/537.36/8mqEpSuL-47",
      "api-key": hybrid_api_key,
    },
  };

  // find the job from jobs
  const job_state = job_states.find((job_state) => job_state.state === state);

  var req = https.request(options, (res_2) => {
    var chunks = [];

    // listen for data event after post request
    res_2.on("data", (chunk) => {
      chunks.push(chunk);
    });

    // listen for end event so we know data has been received
    res_2.on("end", () => {
      var body = Buffer.concat(chunks); // stich all chunks into one

      // parse the response and retrieve only all the scanner name and there result
      const data = JSON.parse(body);

      const scanners = data.scanners.map((scanner) => ({
        name: scanner.name,
        result: parseStatus(scanner.status),
      }));

      // check result if all clean
      const isFileClean = checkMalware(scanners);

      if (isFileClean) {
        // upload file to google drive
        upload_file_to_google_drive(job_state, access_token, res);
      }
    });

    res_2.on("error", function (error) {
      console.error(error);
   
      redirect_to_error_page(res, 500, "failed at uploading file to Hybrid Anylasis malware check");
    });
  });

  function parseStatus(status) {
    if (status === "no-result" || status === "clean" || status === "in-queue") {
      return "clean";
    } else {
      return "malware detected";
    }
  }

  function checkMalware(scanners) {
    for (let i = 0; i < scanners.length; i++) {
      if (scanners[i].result.includes("malware detected")) {
        return false;
      }
    }
    return true;
  }

  // read the content of the file
  var fileContent = fs.readFileSync(job_state.savePath);
  // construct formData with file and scan_type
  var postData =
    "--" +
    "----WebKitFormBoundary7MA4YWxkTrZu0gW\r\n" +
    'Content-Disposition: form-data; name="file"; filename="' +
    path.basename(job_state.savePath) +
    '"\r\n' +
    "Content-Type: application/octet-stream\r\n\r\n" +
    fileContent +
    "\r\n--" +
    "----WebKitFormBoundary7MA4YWxkTrZu0gW\r\n" +
    'Content-Disposition: form-data; name="scan_type"\r\n\r\n' +
    "all_scan\r\n" +
    "--" +
    "----WebKitFormBoundary7MA4YWxkTrZu0gW--";

  req.setHeader(
    "content-type",
    "multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW"
  );

  req.write(postData);

  req.end();
}

function upload_file_to_google_drive(state, access_token, res) {
  // extract file info
  const fileName = path.basename(state.savePath);
  const fileSize = fs.statSync(state.savePath).size;

  // construct our options for gdrive upload
  const options = {
    method: "POST",
    hostname: "www.googleapis.com",
    path: "/upload/drive/v3/files?uploadType=resumable",
    headers: {
      Authorization: `Bearer ${access_token}`,
      "Content-Type": "application/json; charset=UTF-8",
      "X-Upload-Content-Type": "application/octet-stream",
      "X-Upload-Content-Length": fileSize,
      "X-Upload-Content-Disposition": `attachment; filename="${fileName}"`,
    },
  };

  // initiate the file upload to Google drive source (https://developers.google.com/drive/api/guides/manage-uploads#http_1)
  const req = https.request(options, (res_3) => {
    // Get the value of the "location" header from the response, which contains the URL for the actual upload
    const locationHeader = res_3.headers["location"];

    // craete reade stream for our file
    const fileStream = fs.createReadStream(state.savePath);

    // construct upload option
    const uploadOptions = {
      method: "PUT",
      headers: {
        "Content-Length": fileSize,
      },
    };

    // Send a new HTTPS request to upload the file to Google Drive, using the URL retrieved from the previous request
    const uploadReq = https.request(
      locationHeader,
      uploadOptions,
      (uploadRes) => {
        uploadRes.on("data", (data) => {
          console.log(data.toString()); // testing each chunk upload
        });

        uploadRes.on("end", () => {
          console.log("File uploaded successfully!");// testing upload complete
          // redirect user to their google drive page so they can see the upload
          redirect_to_google_drive(state, res);
        });
      }
    );
    
    // pipe the file stream to upload request
    fileStream.pipe(uploadReq);
        
    // error log while uploading
    uploadReq.on("error", (err) => {
      console.error(err);
      // redirect to error page
      redirect_to_error_page(res, 500, "error while uploading to google drive");
    });
  });

  req.on("error", (err) => {
    console.error(err);
    redirect_to_error_page(res, 500, "error while initiating upload to google drive");
  });

  req.write(JSON.stringify({ name: fileName }));

  req.end();
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

function redirect_to_google_drive(state, res) {
	console.log({client_id, scope, state});
    let uri = querystring.stringify({client_id, scope, state});
    // uri is for testing purpose does not effect the redirect
	res.writeHead(302, {Location: `https://drive.google.com/drive/my-drive?${uri}`})
	   .end();
}


function redirect_to_error_page(res, status, message){
	res.writeHead(200, {"Content-Type": "text/html"});
	res.end(`
    <h1>Error Occured</h1> <br>
    <p>Status code:${status} </p> <br>
    <p>Message: ${message}</p><br>
    <a href="${domain}">go home and retry again</p> 
  `);
}