const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: '*' }
});

app.use(express.static(path.join(__dirname, 'public')));
app.get('/health', (req, res) => res.json({ ok: true, rooms: rooms.size }));

const rooms = new Map();
const MAX_MESSAGES_PER_ROOM = 300;

function getRoom(code) {
  if (!rooms.has(code)) {
    rooms.set(code, { messages: [], users: new Map() });
  }
  return rooms.get(code);
}

function presenceList(room) {
  return Array.from(room.users.values());
}

io.on('connection', (socket) => {
  let currentRoom = null;
  let currentName = null;

  socket.on('join_room', ({ name, roomCode }) => {
    if (!name || !roomCode) return;
    currentRoom = String(roomCode).toUpperCase().trim();
    currentName = String(name).trim().slice(0, 24);

    socket.join(currentRoom);
    const room = getRoom(currentRoom);
    room.users.set(socket.id, currentName);

    socket.emit('history', room.messages);
    io.to(currentRoom).emit('presence', presenceList(room));
    socket.to(currentRoom).emit('system_message', `${currentName} joined the room`);
  });

  socket.on('send_message', ({ text }) => {
    if (!currentRoom || !text || !text.trim()) return;
    const room = getRoom(currentRoom);
    const msg = {
      id: Date.now() + '-' + Math.random().toString(36).slice(2, 8),
      sender: currentName,
      senderId: socket.id,
      text: text.trim().slice(0, 4000),
      ts: Date.now()
    };
    room.messages.push(msg);
    if (room.messages.length > MAX_MESSAGES_PER_ROOM) {
      room.messages = room.messages.slice(-MAX_MESSAGES_PER_ROOM);
    }
    io.to(currentRoom).emit('new_message', msg);
  });

  socket.on('typing', (isTyping) => {
    if (!currentRoom) return;
    socket.to(currentRoom).emit('peer_typing', { name: currentName, isTyping: !!isTyping });
  });

  socket.on('disconnect', () => {
    if (!currentRoom) return;
    const room = getRoom(currentRoom);
    room.users.delete(socket.id);
    io.to(currentRoom).emit('presence', presenceList(room));
    socket.to(currentRoom).emit('system_message', `${currentName || 'someone'} left`);
    if (room.users.size === 0 && room.messages.length === 0) {
      rooms.delete(currentRoom);
    }
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log('Nearline server running on port ' + PORT);
});
