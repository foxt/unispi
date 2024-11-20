import { existsSync, readFileSync, writeFileSync } from 'fs';
import http from 'http';
import { MongoClient } from 'mongodb';
import { Readable } from 'stream';
import { parseInformPacket } from "./informpacket.js";

let mongo = new MongoClient("mongodb://localhost:27017");
let db = mongo.db('unispi');
let collections = db.listCollections().toArray();
let transactions = collections.then(async (collections) =>
    collections.find((a) => a.name == 'txns') ||
    await db.createCollection('txns', { timeseries: { timeField: "timestamp", metaField: "meta", granularity: "seconds" } })
).then(() => db.collection('txns'));


let keys: Record<string, string> = {};
if (!existsSync('keys.txt')) 
    writeFileSync('keys.txt', `# This file is used to store the keys used to decrypt the inform packets. One per line.\n# Example: {"mac": "aa:bb:cc:dd:ee:ff", "x_authkey": "ba86f2bbe107c7c57eb5f2690775c712"}\n`);
try {
    let lines = readFileSync('keys.txt').toString().split('\n');
    for (let line of lines) {
        if (line.startsWith("#")) continue;
        if (!line.startsWith("{")) {
            console.warn("Invalid line in keys.txt, ignoring", line);
            continue;
        }
        let {mac, x_authkey: key} = JSON.parse(line.replace(/ObjectId\(([^)]+)\)/g, '$1 '));
        if (typeof mac !== 'string' || typeof key !== 'string') {
            console.warn("Invalid key in keys.txt, ignoring", line);
            continue;
        }
        keys[mac.toLocaleLowerCase()] = key;
    }   
} catch(e) {
    console.error("Failed to load keys.json, ignoring",e )
}
console.log("Loaded keys", keys);




async function tryDumpReqRes(ip: string, reqBody:Buffer, resBody:Buffer) {
    try {
        let req = await parseInformPacket(reqBody, (mac) => keys[mac]);
        if (req.error) throw req.error;

        let res = await parseInformPacket(resBody, (mac) => keys[mac]);
        if (res.error) throw res.error;

        (await transactions).insertOne({
            timestamp: new Date(),
            meta: {
                ip: ip,
                mac: req.head.mac,
            },
            req: {
                head: req.head,
                payload: req.data
            },
            res: {
                head: res.head,
                payload: res.data
            }
        })
    } catch(e) {
        console.error(e)
    }
}

function readToEnd(read: Readable) {
    return new Promise<Buffer>((resolve, reject) => {
        let data = [];
        read.on('data', (chunk) => {
            data.push(chunk);
        });
        read.on('end', () => {
            resolve(Buffer.concat(data));
        });
        read.on('error', reject);
    });
}




const server = http.createServer(async (req, res) => {
    console.log('Request received from ' + req.connection.remoteAddress);
    console.log(`${req.method} ${req.url} HTTP/${req.httpVersion}`);
    for (let header in req.headers) {
        console.log(`${header}: ${req.headers[header]}`);
    }
    console.log(req.url);
    let body = await readToEnd(req);


    let proxiedReq = http.request({
        hostname: '192.168.2.11',
        port: 8080,
        path: '/inform',
        method: 'POST',
        headers: req.headers
    })
    proxiedReq.write(body);
    proxiedReq.end();
    proxiedReq.on('response', async (response) => {
        res.writeHead(response.statusCode, response.headers);
        let data = await readToEnd(response);
        tryDumpReqRes(req.socket.remoteAddress,body, data);

        //writeFileSync('response-' + Date.now() + '.bin', data);
        res.write(data);
        res.end();
    });
    
});
server.listen(8080);