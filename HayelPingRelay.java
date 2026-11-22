import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Pattern;

/**
 * Hayel Ping Relay: forwards Hayel Client sync lines between players in the same room.
 *
 * Run (Java 21+, single file, no dependencies):
 *     java HayelPingRelay.java            port from $PORT, else 25599
 *     java HayelPingRelay.java 30000      explicit port
 *
 * One port speaks three things:
 *  - WebSocket  (ws:// / wss:// behind a hosting provider's HTTPS proxy)  <- Hayel Client default
 *  - plain TCP lines ("host:port" in the client)                          <- older setups
 *  - plain HTTP GET/HEAD  -> "200 OK" (health checks of hosting providers)
 *
 * Protocol: first line/message "HELLO 1 <roomHash>", then "E <sealed>" lines that are
 * copied unchanged to the other members of the room, and "KA" keepalives. The relay
 * never sees room names, server addresses or payload contents (all hashed/encrypted
 * by the clients). Nothing is stored; only connection counts are logged.
 *
 * Limits: 4096 chars per line, 20 lines / 5 s per client, 128 clients per room,
 * 1024 clients total, 120 s idle timeout (clients send keepalives every 25 s).
 */
public final class HayelPingRelay {
    private static final int MAX_LINE = 4096;
    private static final int MAX_PER_ROOM = 128;
    private static final int MAX_CLIENTS = 1024;
    private static final int RATE_LINES = 20;
    private static final long RATE_WINDOW_MS = 5_000L;
    private static final Pattern HELLO = Pattern.compile("HELLO 1 [0-9a-f]{8,64}");
    private static final String WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

    private static final Map<String, Set<Peer>> ROOMS = new ConcurrentHashMap<>();
    private static final AtomicInteger CLIENTS = new AtomicInteger();

    private HayelPingRelay() {}

    public static void main(String[] args) throws IOException {
        String env = System.getenv("PORT");
        int port = args.length > 0 ? Integer.parseInt(args[0]) : env != null ? Integer.parseInt(env.trim()) : 25599;
        try (ServerSocket server = new ServerSocket(port)) {
            log("Hayel Ping Relay listening on port " + port + " (WebSocket + TCP + HTTP health)");
            while (true) {
                Socket s = server.accept();
                Thread.ofVirtual().name("client").start(() -> handle(s));
            }
        }
    }

    // ------------------------------------------------------------------ peers

    /** A connected client, TCP or WebSocket. Outgoing lines go through a queue + writer thread. */
    private abstract static class Peer {
        final Socket socket;
        final OutputStream out;
        final LinkedBlockingQueue<String> queue = new LinkedBlockingQueue<>(256);

        Peer(Socket socket, OutputStream out) {
            this.socket = socket;
            this.out = out;
        }

        abstract void write(String line) throws IOException;

        void writeLoop() {
            try {
                while (true) {
                    write(queue.take());
                    if (queue.isEmpty()) out.flush();
                }
            } catch (InterruptedException | IOException e) {
                close();
            }
        }

        void close() {
            try {
                socket.close();
            } catch (IOException ignored) {
                // already closed
            }
        }
    }

    private static final class TcpPeer extends Peer {
        TcpPeer(Socket s, OutputStream out) {
            super(s, out);
        }

        @Override
        void write(String line) throws IOException {
            out.write((line + "\n").getBytes(StandardCharsets.UTF_8));
        }
    }

    private static final class WsPeer extends Peer {
        WsPeer(Socket s, OutputStream out) {
            super(s, out);
        }

        @Override
        void write(String line) throws IOException {
            writeFrame(out, 0x1, line.getBytes(StandardCharsets.UTF_8));
        }
    }

    /** Reads the next line/message from a client; null when the connection ends. */
    private interface LineSource {
        String next() throws IOException;
    }

    // ------------------------------------------------------------------ connection

    private static void handle(Socket s) {
        if (CLIENTS.incrementAndGet() > MAX_CLIENTS) {
            CLIENTS.decrementAndGet();
            closeQuietly(s);
            return;
        }
        try (s) {
            s.setSoTimeout(120_000);
            s.setTcpNoDelay(true);
            InputStream in = new BufferedInputStream(s.getInputStream());
            OutputStream out = new java.io.BufferedOutputStream(s.getOutputStream());

            String first = readAsciiLine(in);
            if (first == null) return;

            if (first.startsWith("HELLO 1 ")) {                       // plain TCP client
                serve(new TcpPeer(s, out), first, () -> readAsciiLine(in));
            } else if (first.startsWith("GET ") || first.startsWith("HEAD ")) {
                Map<String, String> headers = readHeaders(in);
                String key = headers.get("sec-websocket-key");
                if ("websocket".equalsIgnoreCase(headers.getOrDefault("upgrade", "")) && key != null) {
                    String accept = Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-1")
                            .digest((key.trim() + WS_GUID).getBytes(StandardCharsets.ISO_8859_1)));
                    out.write(("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                            + "Sec-WebSocket-Accept: " + accept + "\r\n\r\n").getBytes(StandardCharsets.ISO_8859_1));
                    out.flush();
                    WsPeer peer = new WsPeer(s, out);
                    String hello = readWsText(in, peer);
                    if (hello != null) serve(peer, hello, () -> readWsText(in, peer));
                } else {                                              // health check / browser
                    byte[] body = "Hayel Ping Relay OK\n".getBytes(StandardCharsets.UTF_8);
                    out.write(("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: " + body.length
                            + "\r\nConnection: close\r\n\r\n").getBytes(StandardCharsets.ISO_8859_1));
                    if (first.startsWith("GET ")) out.write(body);
                    out.flush();
                }
            }
        } catch (Exception ignored) {
            // disconnect / bad client
        } finally {
            CLIENTS.decrementAndGet();
        }
    }

    /** Room membership + forwarding, shared by TCP and WebSocket peers. */
    private static void serve(Peer peer, String hello, LineSource source) throws IOException {
        if (!HELLO.matcher(hello).matches()) return;
        String room = hello.substring("HELLO 1 ".length());
        Set<Peer> members = ROOMS.compute(room, (k, set) -> {
            Set<Peer> m = set != null ? set : ConcurrentHashMap.newKeySet();
            if (m.size() < MAX_PER_ROOM) m.add(peer);
            return m;
        });
        if (!members.contains(peer)) return; // room full

        Thread writer = Thread.ofVirtual().name("writer").start(peer::writeLoop);
        log("join   (rooms: " + ROOMS.size() + ", clients: " + CLIENTS.get() + ")");
        try {
            long windowStart = System.currentTimeMillis();
            int linesInWindow = 0;
            String line;
            while ((line = source.next()) != null) {
                if (!line.startsWith("E ")) continue; // KA and anything else: not forwarded
                long now = System.currentTimeMillis();
                if (now - windowStart > RATE_WINDOW_MS) {
                    windowStart = now;
                    linesInWindow = 0;
                }
                if (++linesInWindow > RATE_LINES) continue;
                for (Peer other : members) {
                    if (other != peer) other.queue.offer(line); // full queue = slow client, drop
                }
            }
        } finally {
            writer.interrupt();
            ROOMS.computeIfPresent(room, (k, set) -> {
                set.remove(peer);
                return set.isEmpty() ? null : set;
            });
            log("leave  (rooms: " + ROOMS.size() + ", clients: " + CLIENTS.get() + ")");
        }
    }

    // ------------------------------------------------------------------ plain lines / HTTP

    /** ASCII line (our protocol and HTTP headers are ASCII); "" if too long, null at end of stream. */
    private static String readAsciiLine(InputStream in) throws IOException {
        StringBuilder sb = new StringBuilder();
        boolean overflow = false;
        int b;
        while ((b = in.read()) != -1) {
            if (b == '\n') return overflow ? "" : sb.toString();
            if (b == '\r') continue;
            if (sb.length() < MAX_LINE) sb.append((char) b);
            else overflow = true;
        }
        return null;
    }

    private static Map<String, String> readHeaders(InputStream in) throws IOException {
        Map<String, String> headers = new HashMap<>();
        String line;
        int count = 0;
        while ((line = readAsciiLine(in)) != null && !line.isEmpty() && count++ < 64) {
            int colon = line.indexOf(':');
            if (colon > 0) headers.put(line.substring(0, colon).trim().toLowerCase(Locale.ROOT), line.substring(colon + 1).trim());
        }
        return headers;
    }

    // ------------------------------------------------------------------ WebSocket frames (RFC 6455)

    /** Next complete text message; answers pings, null on close/end. */
    private static String readWsText(InputStream in, WsPeer peer) throws IOException {
        ByteArrayOutputStream message = new ByteArrayOutputStream();
        while (true) {
            int b0 = in.read();
            int b1 = in.read();
            if (b0 < 0 || b1 < 0) return null;
            boolean fin = (b0 & 0x80) != 0;
            int opcode = b0 & 0x0F;
            boolean masked = (b1 & 0x80) != 0;
            long len = b1 & 0x7F;
            if (len == 126) len = (readByte(in) << 8) | readByte(in);
            else if (len == 127) {
                len = 0;
                for (int i = 0; i < 8; i++) len = (len << 8) | readByte(in);
            }
            if (len > MAX_LINE || len < 0) return null; // too big: drop the client
            byte[] mask = new byte[4];
            if (masked) readFully(in, mask);
            byte[] payload = new byte[(int) len];
            readFully(in, payload);
            if (masked) for (int i = 0; i < payload.length; i++) payload[i] ^= mask[i & 3];

            switch (opcode) {
                case 0x8 -> { // close
                    synchronized (peer.out) {
                        writeFrame(peer.out, 0x8, new byte[0]);
                        peer.out.flush();
                    }
                    return null;
                }
                case 0x9 -> { // ping -> pong
                    synchronized (peer.out) {
                        writeFrame(peer.out, 0xA, payload);
                        peer.out.flush();
                    }
                }
                case 0xA -> { /* pong: ignore */ }
                case 0x1, 0x0 -> { // text / continuation
                    if (message.size() + payload.length > MAX_LINE) return null;
                    message.write(payload);
                    if (fin) return message.toString(StandardCharsets.UTF_8);
                }
                default -> { return null; } // binary or unknown: not ours
            }
        }
    }

    private static void writeFrame(OutputStream out, int opcode, byte[] payload) throws IOException {
        synchronized (out) {
            out.write(0x80 | opcode);
            if (payload.length < 126) {
                out.write(payload.length);
            } else if (payload.length < 65536) {
                out.write(126);
                out.write(payload.length >>> 8);
                out.write(payload.length & 0xFF);
            } else {
                out.write(127);
                for (int i = 7; i >= 0; i--) out.write((int) ((long) payload.length >>> (8 * i)) & 0xFF);
            }
            out.write(payload);
        }
    }

    private static int readByte(InputStream in) throws IOException {
        int b = in.read();
        if (b < 0) throw new EOFException();
        return b;
    }

    private static void readFully(InputStream in, byte[] buf) throws IOException {
        int off = 0;
        while (off < buf.length) {
            int n = in.read(buf, off, buf.length - off);
            if (n < 0) throw new EOFException();
            off += n;
        }
    }

    private static void closeQuietly(Socket s) {
        try {
            s.close();
        } catch (IOException ignored) {
            // nothing to do
        }
    }

    private static void log(String msg) {
        System.out.println("[" + LocalTime.now().format(DateTimeFormatter.ofPattern("HH:mm:ss")) + "] " + msg);
    }
}
