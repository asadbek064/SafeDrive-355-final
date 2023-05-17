/* 
  Asadbek Karimov
  ID: 23607073
  Final Project
 */

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
    domain,
  } = require("./env.json");
  
  var job_states = [];
  
  http
    .createServer(function (req, res) {
      var FAVICON = path.join(__dirname, "public", "favicon.ico");
      var INDEX = path.join(__dirname, "public", "index.html");
      var STYLE = path.join(__dirname, "public", "style.css");
  
      // get requested route path
      var pathname = url.parse(req.url).pathname;
      console.log(pathname);
  
      if (pathname === "/") {
        // serve index.html
        res.writeHead(200, { "Content-Type": "text/html" });
        fs.createReadStream(INDEX).pipe(res);
        return;
      } else if (pathname === "/style.css") {
        // serve styles.css
        res.writeHead(200, { "Content-Type": "text/css" });
        fs.createReadStream(STYLE).pipe(res);
        return;
      } else if (req.method === "GET" && pathname === "/scan-url") {
        // ACCEPT USER INPUT
        let user_input = url.parse(req.url, true).query;
        const { targetURL } = user_input;
        const state = crypto.randomBytes(3).toString("hex");
  
        // append requestedTargetURl and sate to job_states
        job_states.push({ state, targetURL });
        redirect_to_googleauth(state, res);
      } else if (pathname === "/auth/google/callback") {
        // RECEIVE CODE ENDPOINT
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
          redirect_to_error_page(
            res,
            400,
            "/auth/google/callback failed undefined val"
          );
        }
        
  
        send_access_token_request(code, state, res);
      } else if (pathname === "/favicon.ico") {
        // SERVE favicon
        // serve favicon
        res.setHeader("Content-Type", "image/x-icon");
        fs.createReadStream(FAVICON).pipe(res);
        return;
      }
    })
    .listen(3000);
  
  function redirect_to_googleauth(state, res) {
    // Construct the redirect URL
    const redirectUrl = url.format({
      protocol: "https",
      hostname: "accounts.google.com",
      pathname: "/o/oauth2/v2/auth",
      query: {
        response_type: "code",
        client_id: client_id,
        redirect_uri: redirect_uri,
        scope: scope,
        state: state,
      },
    });
  
    // Send the 302 redirect
    res.writeHead(302, { Location: redirectUrl });
    res.end();
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
    console.log('scan_file_for_malware');
    const options = {
      method: "POST",
      hostname: "www.hybrid-analysis.com",
      path: "/api/v2/quick-scan/url",
      headers: {
        "User-Agent":
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.82 Safari/537.36/8mqEpSuL-47",
        "api-key": hybrid_api_key,
      },
    };

    var postData = "------WebKitFormBoundary7MA4YWxkTrZu0gW\r\nContent-Disposition: form-data; name=\"url\"\r\n\r\nhttps://google.com\r\n------WebKitFormBoundary7MA4YWxkTrZu0gW\r\nContent-Disposition: form-data; name=\"scan_type\"\r\n\r\nall_scan\r\n------WebKitFormBoundary7MA4YWxkTrZu0gW--";

  
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
  
        const scanners = data.scanners;
    
        upload_report_to_google_drive(job_state, scanners, access_token, res);
      });
  
      res_2.on("error", function (error) {
        console.error(error);
  
        redirect_to_error_page(
          res,
          500,
          "failed at uploading file to Hybrid Anylasis malware check"
        );
      });
    });
  
    // construct formData with url and scan_type
    var postData = `------WebKitFormBoundary7MA4YWxkTrZu0gW\r\nContent-Disposition: form-data; name=\"url\"\r\n\r\n${job_state.targetURL}\r\n------WebKitFormBoundary7MA4YWxkTrZu0gW\r\nContent-Disposition: form-data; name=\"scan_type\"\r\n\r\nall_scan\r\n------WebKitFormBoundary7MA4YWxkTrZu0gW--`;
  
    req.setHeader(
      "content-type",
      "multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW"
    );
  
    req.write(postData);
  
    req.end();
  }
  
  function upload_report_to_google_drive(job_state, scanners, access_token, res) {
    console.log("upload_report_to_google_drive");
  
    // make scanners detail cleaner
    var scannerDetail = "";
    scanners.forEach(el => {
      scannerDetail += `Name: ${el.name}\n Anti Virus Result: ${JSON.stringify(el.anti_virus_results)} \n Error Message: ${el.error_message}`;
    });
  
    // create a file with all the scanners resulst
    var report = `
      Scanned URL: ${job_state.targetURL}\n
      Full Detail Scan Result:\n
      R: ${scannerDetail}
    `;
  
    console.log(report);
    // save the file
    console.log(__dirname);
    var savePath = `${__dirname}/uploads/Result-${job_state.state}.txt`;
  
    fs.appendFile(savePath, report, function (err) {
      if (err) throw err;
      console.log('Saved!');
  
  
        // extract file info
        const fileName = path.basename(savePath);
        const fileSize = fs.statSync(savePath).size;
  
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
          const fileStream = fs.createReadStream(savePath);
  
          // construct upload option
          const uploadOptions = {
            method: "POST",
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
                console.log("File uploaded successfully!"); // testing upload complete
  
                // since the task is complete remove from the array
                job_states = job_states.filter(function (item) {
                  return item.state !== job_state;
                });

                 // remove file from disk
                fs.unlinkSync(savePath);
                
                // redirect user to their google drive page so they can see the upload
                redirect_to_google_drive(job_state, res);
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
          redirect_to_error_page(
            res,
            500,
            "error while initiating upload to google drive"
          );
        });
  
        req.write(JSON.stringify({ name: fileName }));
        req.end();
    
    });
  
  }
  
  function redirect_to_google_drive(state, res) {
    res
      .writeHead(302, { Location: `https://drive.google.com/drive/my-drive` })
      .end();
  }
  
  function redirect_to_error_page(res, status, message) {
    res.writeHead(200, { "Content-Type": "text/html" });
    res.end(`
        <h1>Error Occured</h1> <br>
        <p>Status code:${status} </p> <br>
        <p>Message: ${message}</p><br>
        <a href="${domain}">go home and retry again</a> 
      `);
  }
  