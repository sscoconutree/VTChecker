const express = require('express');
const fetch = require('node-fetch');
const { sleep, isIPAddress } = require('./helpers');

const app = express();
const API_KEY = 'API_KEY_HERE'; // INSERT YOUR API KEY HERE

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static('public'));

const maxApiRequests = 500;

app.post('/checkEntries', async (req, res) => {
    let apiRequestCount = 0;

    if (apiRequestCount >= maxApiRequests) {
        return res.status(500).json({ success: false });
    }

    const { entries } = req.body;
    const numEntries = entries.length;

    for (let i = 0; i < numEntries; i++) {
        const trimmedEntry = entries[i].trim();

        if (isIPAddress(trimmedEntry)) {
            // Handle IP Address
            const ip = trimmedEntry;
            const url = `https://www.virustotal.com/api/v3/ip_addresses/${ip}`;
            
            try {
                const response = await fetch(url, {
                    headers: {
                        'x-apikey': API_KEY
                    }
                });

                const data = await response.json();
                res.write(JSON.stringify({ type: 'IP', entry: ip, result: data }) + '\n');
            } catch (error) {
                console.error(`Error occurred while checking IP ${ip}:`, error);
                res.write(JSON.stringify({ type: 'IP', entry: ip, error: `Error occurred while checking IP ${ip}.` }) + '\n');
            }
        } else {
            // Handle Hash
            const hash = trimmedEntry;
            let hashType;

            switch (hash.length) {
                case 32:
                    hashType = 'MD5';
                    break;
                case 40:
                    hashType = 'SHA-1';
                    break;
                case 64:
                    hashType = 'SHA-256';
                    break;
                default:
                    hashType = 'Unknown';
            }

            try {
                const response = await fetch(`https://www.virustotal.com/vtapi/v2/file/report?apikey=${API_KEY}&resource=${hash}`);
                apiRequestCount++;

                const result = await response.json();

                let status, enginesDetected;
                if (typeof result.positives === 'undefined') {
                    status = 'Unknown';
                } else if (result.positives !== 0) {
                    status = 'Malicious';
                    enginesDetected = result.positives;
                } else {
                    status = 'Clean';
                }

                const formattedResult = {
                    hash: hash,
                    type: hashType,
                    status: status,
                    enginesDetected: enginesDetected
                };

                res.write(JSON.stringify({ type: 'Hash', entry: hash, result: formattedResult }) + '\n');
            } catch (error) {
                console.error(`Error occurred while checking hash ${hash}:`, error);
                res.write(JSON.stringify({ type: 'Hash', entry: hash, error: `Error occurred while checking hash ${hash}.` }) + '\n');
            }
        }

        if (numEntries >= 4 && i < numEntries - 1) {
            await sleep(15000); 
        }
    }

    res.end(); 
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
