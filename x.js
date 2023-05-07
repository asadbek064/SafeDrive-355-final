function handleFileUpload(req, hash, callback) {
    const chunks = [];
  
    // save all chunk to chunks
    req.on("data", (chunk) => {
      chunks.push(chunk);
    });
    req.on("end", () => {
      // stich all chunks
      const data = Buffer.concat(chunks);
  
      // Parse the multipart form data
      const boundary = contentType.split("; ")[1].split("=")[1];
      const parts = data.toString().split(`--${boundary}`);
  
      for (let i = 1; i < parts.length - 1; i++) {
        const part = parts[i].trim(); // extract current part and remove whitespaces
  
        // find end of the section by matching patterns [two empty new lines indicates that 2xCRLF](https://www.w3.org/TR/html401/interact/forms.html#h-17.13.4)
        const headerEnd = part.indexOf("\r\n\r\n");
  
        // extract header and content
        const header = part.substring(0, headerEnd);
        const content = part.substring(headerEnd + 4, part.length - 2);
        const filenameMatch = header.match(/filename="([^"]+)"/); // find string that starts with filename=" plus anther character that is not double quote
        // extract filename
        let _filename = "";
  
  
        if (filenameMatch) {
          _filename = filenameMatch[1] + hash;
        } else {
          // no filename
          _filename = "untitled-" + hash;
        }
  
  
        if (_filename) {
          // save file to disk
          const extension = _filename.split(".").pop(); // extract file type
          const savePath = `./uploads/${_filename}.${extension}`; // construct the path to save to
          fs.writeFile(savePath, content, (err) => { // save file
            if (err) {
              callback(err, null);
            } else {
              console.log(`Saved file to ${savePath}`);
              callback(null, savePath);
            }
          });
        }
      }
    });
  }
  