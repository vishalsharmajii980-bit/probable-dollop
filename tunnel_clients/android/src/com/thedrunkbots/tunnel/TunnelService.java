package com.thedrunkbots.tunnel;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkRequest;
import android.net.wifi.WifiManager;
import android.os.Build;
import android.os.IBinder;
import android.os.PowerManager;
import android.provider.Settings;
import android.util.Base64;

import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

public class TunnelService extends Service {
    public static final String CHANNEL_ID = "tdb_tunnel_channel";
    public static final AtomicBoolean IS_RUNNING = new AtomicBoolean(false);
    public static final AtomicBoolean WS_CONNECTED = new AtomicBoolean(false);
    public static final AtomicInteger TOTAL_CONNS = new AtomicInteger(0);
    public static volatile String STATUS_TEXT = "Stopped";
    public static volatile String PUBLIC_IP = "Detecting...";
    public static volatile String ISP_INFO = "";
    public static volatile String DEVICE_ID = "";
    public static final List<String> LOG_LINES = new ArrayList<>();

    private PowerManager.WakeLock wakeLock;
    private WifiManager.WifiLock wifiLock;
    private ConnectivityManager.NetworkCallback netCallback;
    private ExecutorService pool;
    private volatile Socket activeWsSocket;
    private final Object wsSendLock = new Object();
    private final Map<Integer, Socket> activeStreams = new ConcurrentHashMap<>();
    private final SecureRandom rng = new SecureRandom();

    public static synchronized void addLog(String msg) {
        String ts = new SimpleDateFormat("HH:mm:ss", Locale.US).format(new Date());
        LOG_LINES.add("[" + ts + "] " + msg);
        if (LOG_LINES.size() > 120) {
            LOG_LINES.remove(0);
        }
    }

    public static synchronized String getLogsText() {
        StringBuilder sb = new StringBuilder();
        for (String line : LOG_LINES) {
            sb.append(line).append("\n");
        }
        return sb.toString();
    }

    public static String getOrInitDeviceId(Context ctx) {
        SharedPreferences prefs = ctx.getSharedPreferences("tdb_tunnel_prefs", Context.MODE_PRIVATE);
        String saved = prefs.getString("device_id", null);
        if (saved != null && !saved.isEmpty()) {
            DEVICE_ID = saved;
            return saved;
        }
        String aid = "";
        try {
            aid = Settings.Secure.getString(ctx.getContentResolver(), Settings.Secure.ANDROID_ID);
        } catch (Exception ignored) {}
        if (aid == null || aid.isEmpty()) {
            aid = Long.toHexString(System.currentTimeMillis());
        }
        String model = (Build.MODEL != null ? Build.MODEL : "android")
                .replaceAll("[^a-zA-Z0-9]+", "-").toLowerCase(Locale.US);
        String id = "android-" + model + "-" + (aid.length() > 6 ? aid.substring(0, 6) : aid);
        prefs.edit().putString("device_id", id).apply();
        DEVICE_ID = id;
        return id;
    }

    @Override
    public void onCreate() {
        super.onCreate();
        pool = Executors.newCachedThreadPool();
        getOrInitDeviceId(this);
        acquireLocks();
        registerNetworkCallback();
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null && "STOP".equals(intent.getAction())) {
            stopSelf();
            return START_NOT_STICKY;
        }
        startForeground(1001, buildNotification("Starting Background Tunnel..."));
        if (IS_RUNNING.compareAndSet(false, true)) {
            STATUS_TEXT = "Connecting...";
            addLog("Foreground Tunnel Service started (" + DEVICE_ID + ")");
            pool.execute(this::tunnelMainLoop);
            pool.execute(this::heartbeatLoop);
        } else if (intent != null && "FORCE_SYNC".equals(intent.getAction())) {
            addLog("Manual re-sync requested");
            pool.execute(() -> {
                detectPublicIp();
                sendHttpHeartbeat(true);
            });
        }
        return START_STICKY;
    }

    private void acquireLocks() {
        try {
            PowerManager pm = (PowerManager) getSystemService(Context.POWER_SERVICE);
            if (pm != null) {
                wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "TheDrunkBots::TunnelWakeLock");
                wakeLock.setReferenceCounted(false);
                wakeLock.acquire();
            }
            WifiManager wm = (WifiManager) getApplicationContext().getSystemService(Context.WIFI_SERVICE);
            if (wm != null) {
                wifiLock = wm.createWifiLock(WifiManager.WIFI_MODE_FULL_HIGH_PERF, "TheDrunkBots::TunnelWifiLock");
                wifiLock.setReferenceCounted(false);
                wifiLock.acquire();
            }
        } catch (Exception e) {
            addLog("Lock warning: " + e.getMessage());
        }
    }

    private void registerNetworkCallback() {
        try {
            ConnectivityManager cm = (ConnectivityManager) getSystemService(Context.CONNECTIVITY_SERVICE);
            if (cm == null) return;
            NetworkRequest req = new NetworkRequest.Builder()
                    .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                    .build();
            netCallback = new ConnectivityManager.NetworkCallback() {
                @Override
                public void onAvailable(Network network) {
                    addLog("Network available — refreshing IP & tunnel");
                    if (pool != null && !pool.isShutdown()) {
                        pool.execute(() -> {
                            detectPublicIp();
                            sendHttpHeartbeat(false);
                        });
                    }
                }

                @Override
                public void onLost(Network network) {
                    addLog("Network connection lost — waiting for reconnect");
                    STATUS_TEXT = "Waiting for internet...";
                    updateNotification(STATUS_TEXT);
                    closeActiveWs();
                }
            };
            cm.registerNetworkCallback(req, netCallback);
        } catch (Exception ignored) {}
    }

    private Notification buildNotification(String text) {
        NotificationManager nm = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
        if (Build.VERSION.SDK_INT >= 26 && nm != null) {
            NotificationChannel ch = new NotificationChannel(
                    CHANNEL_ID,
                    "TheDrunkBots Tunnel Service",
                    NotificationManager.IMPORTANCE_LOW
            );
            nm.createNotificationChannel(ch);
        }
        Intent openIntent = new Intent(this, MainActivity.class);
        int piFlags = Build.VERSION.SDK_INT >= 23 ? PendingIntent.FLAG_IMMUTABLE : 0;
        PendingIntent pi = PendingIntent.getActivity(this, 0, openIntent, piFlags);

        Notification.Builder b = Build.VERSION.SDK_INT >= 26
                ? new Notification.Builder(this, CHANNEL_ID)
                : new Notification.Builder(this);
        b.setContentTitle("TheDrunkBots Auto Tunnel")
                .setContentText(text)
                .setSmallIcon(android.R.drawable.stat_sys_upload_done)
                .setContentIntent(pi)
                .setOngoing(true);
        return b.build();
    }

    private void updateNotification(String text) {
        try {
            NotificationManager nm = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
            if (nm != null) {
                nm.notify(1001, buildNotification(text));
            }
        } catch (Exception ignored) {}
    }

    private void detectPublicIp() {
        try {
            URL u = new URL("https://ipinfo.io/json");
            HttpURLConnection conn = (HttpURLConnection) u.openConnection();
            conn.setConnectTimeout(7000);
            conn.setReadTimeout(7000);
            conn.setRequestProperty("User-Agent", "Mozilla/5.0");
            if (conn.getResponseCode() == 200) {
                BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream()));
                StringBuilder sb = new StringBuilder();
                String line;
                while ((line = br.readLine()) != null) sb.append(line);
                br.close();
                JSONObject j = new JSONObject(sb.toString());
                PUBLIC_IP = j.optString("ip", PUBLIC_IP);
                String org = j.optString("org", "");
                String city = j.optString("city", "");
                String country = j.optString("country", "");
                ISP_INFO = (org + " (" + city + ", " + country + ")").trim();
            }
            conn.disconnect();
        } catch (Exception ignored) {}
    }

    private JSONObject buildDeviceJson() throws Exception {
        SharedPreferences prefs = getSharedPreferences("tdb_tunnel_prefs", MODE_PRIVATE);
        String defName = (Build.MANUFACTURER + " " + Build.MODEL).trim();
        String devName = prefs.getString("device_name", defName);
        if (devName == null || devName.trim().isEmpty()) devName = defName;

        JSONObject obj = new JSONObject();
        obj.put("device_id", getOrInitDeviceId(this));
        obj.put("device_name", devName);
        obj.put("device_type", "android");
        obj.put("platform_info", "Android " + Build.VERSION.RELEASE + " (" + Build.MODEL + ")");
        obj.put("tunnel_mode", "ws");
        obj.put("public_ip", PUBLIC_IP);
        obj.put("isp", ISP_INFO);
        obj.put("status", WS_CONNECTED.get() ? "online" : "reconnecting");
        obj.put("total_requests", TOTAL_CONNS.get());
        return obj;
    }

    private void sendHttpHeartbeat(boolean register) {
        try {
            SharedPreferences prefs = getSharedPreferences("tdb_tunnel_prefs", MODE_PRIVATE);
            String srv = prefs.getString("server_url", "").trim();
            String secret = prefs.getString("secret", "admin123").trim();
            if (srv.isEmpty()) return;
            if (srv.endsWith("/")) srv = srv.substring(0, srv.length() - 1);

            String endpoint = register ? "/api/tunnels/register" : "/api/tunnels/heartbeat";
            URL u = new URL(srv + endpoint);
            HttpURLConnection conn = (HttpURLConnection) u.openConnection();
            conn.setRequestMethod("POST");
            conn.setConnectTimeout(8000);
            conn.setReadTimeout(8000);
            conn.setDoOutput(true);
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("Authorization", "Bearer " + secret);
            conn.setRequestProperty("X-Tunnel-Secret", secret);

            byte[] body = buildDeviceJson().toString().getBytes(StandardCharsets.UTF_8);
            OutputStream os = conn.getOutputStream();
            os.write(body);
            os.flush();
            os.close();
            int code = conn.getResponseCode();
            conn.disconnect();
            if (code == 200 && register) {
                addLog("Registered device with Admin Panel (" + PUBLIC_IP + ")");
            }
        } catch (Exception ignored) {}
    }

    private void heartbeatLoop() {
        detectPublicIp();
        sendHttpHeartbeat(true);
        while (IS_RUNNING.get()) {
            try {
                Thread.sleep(15000);
                if (!IS_RUNNING.get()) break;
                detectPublicIp();
                sendHttpHeartbeat(false);
            } catch (InterruptedException e) {
                break;
            }
        }
    }

    private void tunnelMainLoop() {
        while (IS_RUNNING.get()) {
            SharedPreferences prefs = getSharedPreferences("tdb_tunnel_prefs", MODE_PRIVATE);
            String srv = prefs.getString("server_url", "").trim();
            String secret = prefs.getString("secret", "admin123").trim();
            if (srv.isEmpty()) {
                STATUS_TEXT = "Set Backend Server URL in App";
                updateNotification(STATUS_TEXT);
                try { Thread.sleep(4000); } catch (InterruptedException e) { break; }
                continue;
            }
            try {
                runWebSocketSession(srv, secret);
            } catch (Exception e) {
                WS_CONNECTED.set(false);
                STATUS_TEXT = "Reconnecting in 4s...";
                updateNotification(STATUS_TEXT);
                addLog("Tunnel disconnected: " + e.getMessage());
                try { Thread.sleep(4000); } catch (InterruptedException ie) { break; }
            }
        }
    }

    private void runWebSocketSession(String srvUrl, String secret) throws Exception {
        if (srvUrl.endsWith("/")) srvUrl = srvUrl.substring(0, srvUrl.length() - 1);
        URI uri = new URI(srvUrl);
        boolean tls = "https".equalsIgnoreCase(uri.getScheme()) || "wss".equalsIgnoreCase(uri.getScheme());
        String host = uri.getHost();
        int port = uri.getPort() != -1 ? uri.getPort() : (tls ? 443 : 80);
        String path = "/api/tunnels/ws?key=" + URLEncoder.encode(secret, "UTF-8");

        STATUS_TEXT = "Connecting to " + host + "...";
        updateNotification(STATUS_TEXT);

        Socket raw = new Socket();
        raw.connect(new InetSocketAddress(host, port), 15000);
        Socket sock;
        if (tls) {
            SSLSocketFactory sf = (SSLSocketFactory) SSLSocketFactory.getDefault();
            SSLSocket sslSock = (SSLSocket) sf.createSocket(raw, host, port, true);
            sslSock.startHandshake();
            sock = sslSock;
        } else {
            sock = raw;
        }
        sock.setSoTimeout(65000);
        activeWsSocket = sock;

        byte[] keyBytes = new byte[16];
        rng.nextBytes(keyBytes);
        String wsKey = Base64.encodeToString(keyBytes, Base64.NO_WRAP);

        String req = "GET " + path + " HTTP/1.1\r\n" +
                "Host: " + host + ":" + port + "\r\n" +
                "Upgrade: websocket\r\n" +
                "Connection: Upgrade\r\n" +
                "Sec-WebSocket-Key: " + wsKey + "\r\n" +
                "Sec-WebSocket-Version: 13\r\n" +
                "Authorization: Bearer " + secret + "\r\n" +
                "X-Tunnel-Secret: " + secret + "\r\n\r\n";

        InputStream in = sock.getInputStream();
        OutputStream out = sock.getOutputStream();
        out.write(req.getBytes(StandardCharsets.UTF_8));
        out.flush();

        ByteArrayOutputStream hdrBuf = new ByteArrayOutputStream();
        int b;
        while ((b = in.read()) != -1) {
            hdrBuf.write(b);
            byte[] cur = hdrBuf.toByteArray();
            int n = cur.length;
            if (n >= 4 && cur[n - 4] == '\r' && cur[n - 3] == '\n' && cur[n - 2] == '\r' && cur[n - 1] == '\n') {
                break;
            }
        }
        String hdrStr = new String(hdrBuf.toByteArray(), StandardCharsets.ISO_8859_1);
        if (!hdrStr.contains("101")) {
            sock.close();
            throw new Exception("Handshake rejected: " + hdrStr.split("\r\n")[0]);
        }

        WS_CONNECTED.set(true);
        STATUS_TEXT = "Connected & Active (" + PUBLIC_IP + ")";
        updateNotification(STATUS_TEXT);
        addLog("Connected to Backend WebSocket Tunnel!");

        JSONObject hello = buildDeviceJson();
        hello.put("type", "hello");
        wsSendJson(out, hello);

        // Background WS ping thread
        pool.execute(() -> {
            while (IS_RUNNING.get() && WS_CONNECTED.get() && activeWsSocket == sock) {
                try {
                    Thread.sleep(20000);
                    if (!WS_CONNECTED.get() || activeWsSocket != sock) break;
                    JSONObject ping = new JSONObject();
                    ping.put("type", "ping");
                    ping.put("public_ip", PUBLIC_IP);
                    ping.put("isp", ISP_INFO);
                    ping.put("conns", TOTAL_CONNS.get());
                    wsSendJson(out, ping);
                } catch (Exception e) {
                    break;
                }
            }
        });

        try {
            while (IS_RUNNING.get()) {
                int b0 = in.read();
                int b1 = in.read();
                if (b0 == -1 || b1 == -1) break;
                int opcode = b0 & 0x0F;
                boolean masked = (b1 & 0x80) != 0;
                long len = b1 & 0x7F;
                if (len == 126) {
                    byte[] ext = readExact(in, 2);
                    len = ((ext[0] & 0xFF) << 8) | (ext[1] & 0xFF);
                } else if (len == 127) {
                    byte[] ext = readExact(in, 8);
                    len = ByteBuffer.wrap(ext).getLong();
                }
                byte[] maskKey = masked ? readExact(in, 4) : null;
                byte[] payload = len > 0 ? readExact(in, (int) len) : new byte[0];
                if (masked && maskKey != null) {
                    for (int i = 0; i < payload.length; i++) {
                        payload[i] ^= maskKey[i & 3];
                    }
                }

                if (opcode == 0x8) {
                    break;
                } else if (opcode == 0x9) {
                    wsSendFrame(out, 0xA, payload);
                } else if (opcode == 0x1) {
                    JSONObject msg = new JSONObject(new String(payload, StandardCharsets.UTF_8));
                    String type = msg.optString("type");
                    if ("open".equals(type)) {
                        int sid = msg.optInt("stream_id");
                        String thost = msg.optString("host");
                        int tport = msg.optInt("port", 443);
                        String ib64 = msg.optString("init_b64", "");
                        pool.execute(() -> handleOpenStream(out, sid, thost, tport, ib64));
                    } else if ("close".equals(type)) {
                        int sid = msg.optInt("stream_id");
                        Socket s = activeStreams.remove(sid);
                        if (s != null) {
                            try { s.close(); } catch (Exception ignored) {}
                        }
                    }
                } else if (opcode == 0x2) {
                    if (payload.length >= 4) {
                        int sid = ByteBuffer.wrap(payload, 0, 4).getInt();
                        Socket s = activeStreams.get(sid);
                        if (s != null) {
                            try {
                                OutputStream sOut = s.getOutputStream();
                                sOut.write(payload, 4, payload.length - 4);
                                sOut.flush();
                            } catch (Exception e) {
                                activeStreams.remove(sid);
                                try { s.close(); } catch (Exception ignored) {}
                            }
                        }
                    }
                }
            }
        } finally {
            WS_CONNECTED.set(false);
            for (Socket s : activeStreams.values()) {
                try { s.close(); } catch (Exception ignored) {}
            }
            activeStreams.clear();
            try { sock.close(); } catch (Exception ignored) {}
        }
    }

    private void handleOpenStream(OutputStream wsOut, int sid, String host, int port, String initB64) {
        Socket up = null;
        try {
            up = new Socket();
            up.connect(new InetSocketAddress(host, port), 18000);
            up.setSoTimeout(120000);
            if (initB64 != null && !initB64.isEmpty()) {
                byte[] initBytes = Base64.decode(initB64, Base64.DEFAULT);
                up.getOutputStream().write(initBytes);
                up.getOutputStream().flush();
            }
            activeStreams.put(sid, up);
            TOTAL_CONNS.incrementAndGet();

            JSONObject ok = new JSONObject();
            ok.put("type", "open_ok");
            ok.put("stream_id", sid);
            wsSendJson(wsOut, ok);

            InputStream upIn = up.getInputStream();
            byte[] buf = new byte[32768];
            int n;
            while (IS_RUNNING.get() && (n = upIn.read(buf)) != -1) {
                if (n > 0) {
                    byte[] framePayload = new byte[4 + n];
                    ByteBuffer.wrap(framePayload, 0, 4).putInt(sid);
                    System.arraycopy(buf, 0, framePayload, 4, n);
                    wsSendFrame(wsOut, 0x2, framePayload);
                }
            }
        } catch (Exception e) {
            try {
                JSONObject err = new JSONObject();
                err.put("type", "open_err");
                err.put("stream_id", sid);
                err.put("error", String.valueOf(e.getMessage()));
                wsSendJson(wsOut, err);
            } catch (Exception ignored) {}
        } finally {
            activeStreams.remove(sid);
            if (up != null) {
                try { up.close(); } catch (Exception ignored) {}
            }
            try {
                JSONObject cl = new JSONObject();
                cl.put("type", "close");
                cl.put("stream_id", sid);
                wsSendJson(wsOut, cl);
            } catch (Exception ignored) {}
        }
    }

    private byte[] readExact(InputStream in, int len) throws Exception {
        byte[] buf = new byte[len];
        int off = 0;
        while (off < len) {
            int r = in.read(buf, off, len - off);
            if (r == -1) throw new Exception("WebSocket EOF");
            off += r;
        }
        return buf;
    }

    private void wsSendJson(OutputStream out, JSONObject obj) throws Exception {
        wsSendFrame(out, 0x1, obj.toString().getBytes(StandardCharsets.UTF_8));
    }

    private void wsSendFrame(OutputStream out, int opcode, byte[] payload) throws Exception {
        byte[] mask = new byte[4];
        rng.nextBytes(mask);
        int len = payload.length;
        ByteArrayOutputStream frame = new ByteArrayOutputStream(len + 14);
        frame.write(0x80 | (opcode & 0x0F));
        if (len < 126) {
            frame.write(0x80 | len);
        } else if (len < 65536) {
            frame.write(0x80 | 126);
            frame.write((len >> 8) & 0xFF);
            frame.write(len & 0xFF);
        } else {
            frame.write(0x80 | 127);
            ByteBuffer bb = ByteBuffer.allocate(8);
            bb.putLong(len);
            frame.write(bb.array());
        }
        frame.write(mask);
        byte[] masked = new byte[len];
        for (int i = 0; i < len; i++) {
            masked[i] = (byte) (payload[i] ^ mask[i & 3]);
        }
        frame.write(masked);
        synchronized (wsSendLock) {
            out.write(frame.toByteArray());
            out.flush();
        }
    }

    private void closeActiveWs() {
        Socket s = activeWsSocket;
        activeWsSocket = null;
        if (s != null) {
            try { s.close(); } catch (Exception ignored) {}
        }
    }

    @Override
    public void onDestroy() {
        IS_RUNNING.set(false);
        WS_CONNECTED.set(false);
        STATUS_TEXT = "Stopped";
        closeActiveWs();
        try {
            if (netCallback != null) {
                ConnectivityManager cm = (ConnectivityManager) getSystemService(Context.CONNECTIVITY_SERVICE);
                if (cm != null) cm.unregisterNetworkCallback(netCallback);
            }
        } catch (Exception ignored) {}
        try {
            if (wakeLock != null && wakeLock.isHeld()) wakeLock.release();
            if (wifiLock != null && wifiLock.isHeld()) wifiLock.release();
        } catch (Exception ignored) {}
        if (pool != null) pool.shutdownNow();
        super.onDestroy();
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }
}
