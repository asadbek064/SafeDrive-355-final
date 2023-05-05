var http = require('http');
var url = require('url');
var fs = require('fs');
var path = require('path');
var crypto = require('crypto');

var jobs = [];

http.createServer(function (req, res) {
    var FAVICON = path.join(__dirname, 'public', 'favicon.ico');
    var INDEX = path.join(__dirname, 'public', 'index.html');

    // get requested route path
    var pathname = url.parse(req.url).pathname;
    console.log(pathname);

    if (pathname === '/') { // serve index.html
        res.writeHead(200, {'Content-Type': 'text/html'});
        fs.createReadStream(INDEX).pipe(res);
        return;

    }else if (req.method === 'POST' && pathname === '/upload-file') {
        // accept the file and store it in tmp folder
        const hash = generateShortHash();
        const fileName = req.headers['x-filename'] || `untitled-${hash}`; // get file name if not provided use the hash as file name
        const filePath = './tmp-uploads/' + fileName;
        const fileStream = fs.createWriteStream(filePath);

        // save the data to file system
        req.on('data', (chunk) => {
            fileStream.write(chunk);
        });

        req.on('end', () => {
            // create a unique key value pair format { hash: filename}  and append to jobs
            jobs.push({task:`${hash}`, state: filePath});
            
            // send ok respond
            fileStream.end();
            
            // redirect user to google sigin to a
            const options = {
                'method': 'POST',
                'hostname': 'accounts.google.com',
                'path': '/o/oauth2/auth',
                'headers': {
                  'scope': 'https://www.googleapis.com/auth/drive',
                  'client_id': '669553241597-sjgkef797rcnuks50c3fo37eojrunsgq.apps.googleusercontent.com',
                  'redirect_uri': 'https://oauth.pstmn.io/v1/callback',
                  'response_type': 'code',
                  'status': `${hash}`
                },
                'maxRedirects': 20
              };

              res.writeHead(302, { 'Location': options.headers.redirect_uri });
              res.end();
        });

    } else if (pathname === '/favicon.ico') { // serve favicon 
        res.setHeader('Content-Type', 'image/x-icon');
        fs.createReadStream(FAVICON).pipe(res);
        return;
    }

}).listen(8081);

function generateShortHash() {
    const hash = crypto.randomBytes(6).toString('hex');
    return hash.toUpperCase();
  }

