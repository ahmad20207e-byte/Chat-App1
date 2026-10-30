# Chat App (دردشة)

Group room + private 1-to-1 chats, accounts (hashed passwords), SQLite database, real-time via WebSocket.

## Run locally
    npm install
    npm start        # http://localhost:3000

## Deploy (Render.com, free)
1. Push this folder to a GitHub repo.
2. Render -> New -> Web Service -> pick the repo.
3. Build command: `npm install`   Start command: `npm start`
4. Environment variables: `JWT_SECRET` = any long random string.
5. For data that survives restarts, add a Disk (e.g. mount `/data`) and set `DATA_DIR=/data`.
   (Without a disk, the free tier resets the database on each deploy.)

Railway / Fly.io / any VPS with Node 18+ also work.
