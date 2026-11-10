package com.thedrunkbots.tunnel;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Build;

public class BootReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
        if (intent == null || intent.getAction() == null) return;
        SharedPreferences prefs = context.getSharedPreferences("tdb_tunnel_prefs", Context.MODE_PRIVATE);
        boolean autoStart = prefs.getBoolean("service_enabled", true);
        String srvUrl = prefs.getString("server_url", "");
        if (autoStart && srvUrl != null && !srvUrl.trim().isEmpty()) {
            Intent svc = new Intent(context, TunnelService.class);
            if (Build.VERSION.SDK_INT >= 26) {
                context.startForegroundService(svc);
            } else {
                context.startService(svc);
            }
        }
    }
}
