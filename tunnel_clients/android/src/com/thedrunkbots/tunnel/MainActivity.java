package com.thedrunkbots.tunnel;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.PowerManager;
import android.provider.Settings;
import android.text.InputType;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

public class MainActivity extends Activity {
    private TextView statusBadge;
    private TextView deviceInfoTv;
    private TextView ipInfoTv;
    private TextView logTv;
    private EditText devNameInput;
    private EditText srvUrlInput;
    private EditText secretInput;
    private Button toggleBtn;
    private Handler uiHandler;
    private Runnable uiTicker;

    private int dp(int v) {
        return Math.round(v * getResources().getDisplayMetrics().density);
    }

    private GradientDrawable roundedBg(int fillColor, int strokeColor, int radiusDp) {
        GradientDrawable gd = new GradientDrawable();
        gd.setColor(fillColor);
        gd.setCornerRadius(dp(radiusDp));
        if (strokeColor != 0) {
            gd.setStroke(dp(1), strokeColor);
        }
        return gd;
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        SharedPreferences prefs = getSharedPreferences("tdb_tunnel_prefs", MODE_PRIVATE);
        String defaultDevName = (Build.MANUFACTURER + " " + Build.MODEL).trim();
        String savedDevName = prefs.getString("device_name", defaultDevName);
        String savedSrvUrl = prefs.getString("server_url", "");
        String savedSecret = prefs.getString("secret", "admin123");
        String devId = TunnelService.getOrInitDeviceId(this);

        ScrollView scroll = new ScrollView(this);
        scroll.setBackgroundColor(Color.parseColor("#080C14"));
        scroll.setFillViewport(true);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(dp(18), dp(22), dp(18), dp(24));
        scroll.addView(root);

        // Header Card
        LinearLayout headerCard = new LinearLayout(this);
        headerCard.setOrientation(LinearLayout.VERTICAL);
        headerCard.setPadding(dp(18), dp(16), dp(18), dp(16));
        headerCard.setBackground(roundedBg(Color.parseColor("#111827"), Color.parseColor("#1E293B"), 16));
        root.addView(headerCard);

        TextView title = new TextView(this);
        title.setText("TheDrunkBots Tunnel");
        title.setTextColor(Color.WHITE);
        title.setTextSize(21);
        title.setTypeface(Typeface.DEFAULT_BOLD);
        headerCard.addView(title);

        TextView subtitle = new TextView(this);
        subtitle.setText("24/7 Background Mobile Proxy Tunnel & Admin Auto-Sync");
        subtitle.setTextColor(Color.parseColor("#94A3B8"));
        subtitle.setTextSize(12);
        subtitle.setPadding(0, dp(4), 0, dp(12));
        headerCard.addView(subtitle);

        statusBadge = new TextView(this);
        statusBadge.setText("STATUS: STOPPED");
        statusBadge.setTextColor(Color.parseColor("#34D399"));
        statusBadge.setTextSize(13);
        statusBadge.setTypeface(Typeface.MONOSPACE, Typeface.BOLD);
        statusBadge.setPadding(dp(12), dp(8), dp(12), dp(8));
        statusBadge.setBackground(roundedBg(Color.parseColor("#0F172A"), Color.parseColor("#334155"), 10));
        headerCard.addView(statusBadge);

        deviceInfoTv = new TextView(this);
        deviceInfoTv.setText("Device ID: " + devId);
        deviceInfoTv.setTextColor(Color.parseColor("#CBD5E1"));
        deviceInfoTv.setTextSize(12);
        deviceInfoTv.setTypeface(Typeface.MONOSPACE);
        deviceInfoTv.setPadding(0, dp(10), 0, dp(2));
        headerCard.addView(deviceInfoTv);

        ipInfoTv = new TextView(this);
        ipInfoTv.setText("Public IP: Detecting...");
        ipInfoTv.setTextColor(Color.parseColor("#38BDF8"));
        ipInfoTv.setTextSize(12);
        ipInfoTv.setTypeface(Typeface.MONOSPACE);
        headerCard.addView(ipInfoTv);

        // Config Card
        LinearLayout cfgCard = new LinearLayout(this);
        cfgCard.setOrientation(LinearLayout.VERTICAL);
        cfgCard.setPadding(dp(18), dp(16), dp(18), dp(16));
        cfgCard.setBackground(roundedBg(Color.parseColor("#111827"), Color.parseColor("#1E293B"), 16));
        LinearLayout.LayoutParams cfgLp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        cfgLp.topMargin = dp(14);
        root.addView(cfgCard, cfgLp);

        devNameInput = addLabeledInput(cfgCard, "DEVICE NAME (SHOWN IN ADMIN PANEL)", savedDevName, false);
        srvUrlInput = addLabeledInput(cfgCard, "BACKEND SERVER URL (https://...)", savedSrvUrl, false);
        secretInput = addLabeledInput(cfgCard, "ADMIN PASSWORD / TUNNEL SECRET", savedSecret, true);

        // Action Buttons
        toggleBtn = new Button(this);
        toggleBtn.setText("START BACKGROUND TUNNEL");
        toggleBtn.setTextColor(Color.WHITE);
        toggleBtn.setTextSize(14);
        toggleBtn.setTypeface(Typeface.DEFAULT_BOLD);
        toggleBtn.setPadding(dp(14), dp(14), dp(14), dp(14));
        toggleBtn.setBackground(roundedBg(Color.parseColor("#10B981"), 0, 12));
        LinearLayout.LayoutParams btnLp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        btnLp.topMargin = dp(14);
        cfgCard.addView(toggleBtn, btnLp);

        LinearLayout rowBtns = new LinearLayout(this);
        rowBtns.setOrientation(LinearLayout.HORIZONTAL);
        LinearLayout.LayoutParams rowLp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        rowLp.topMargin = dp(10);
        cfgCard.addView(rowBtns, rowLp);

        Button syncBtn = new Button(this);
        syncBtn.setText("SAVE & SYNC NOW");
        syncBtn.setTextColor(Color.WHITE);
        syncBtn.setTextSize(12);
        syncBtn.setTypeface(Typeface.DEFAULT_BOLD);
        syncBtn.setBackground(roundedBg(Color.parseColor("#6366F1"), 0, 10));
        LinearLayout.LayoutParams halfLp1 = new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f);
        halfLp1.rightMargin = dp(6);
        rowBtns.addView(syncBtn, halfLp1);

        Button battBtn = new Button(this);
        battBtn.setText("ALLOW 24/7 BACKGROUND");
        battBtn.setTextColor(Color.WHITE);
        battBtn.setTextSize(12);
        battBtn.setTypeface(Typeface.DEFAULT_BOLD);
        battBtn.setBackground(roundedBg(Color.parseColor("#334155"), 0, 10));
        LinearLayout.LayoutParams halfLp2 = new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f);
        halfLp2.leftMargin = dp(6);
        rowBtns.addView(battBtn, halfLp2);

        toggleBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                saveSettings();
                if (TunnelService.IS_RUNNING.get()) {
                    prefs.edit().putBoolean("service_enabled", false).apply();
                    Intent stop = new Intent(MainActivity.this, TunnelService.class);
                    stop.setAction("STOP");
                    startService(stop);
                    Toast.makeText(MainActivity.this, "Background tunnel stopped", Toast.LENGTH_SHORT).show();
                } else {
                    String u = srvUrlInput.getText().toString().trim();
                    if (u.isEmpty()) {
                        Toast.makeText(MainActivity.this, "Please enter Backend Server URL first", Toast.LENGTH_LONG).show();
                        return;
                    }
                    prefs.edit().putBoolean("service_enabled", true).apply();
                    startTunnelService("START");
                    Toast.makeText(MainActivity.this, "Background tunnel started!", Toast.LENGTH_SHORT).show();
                }
            }
        });

        syncBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                saveSettings();
                if (!TunnelService.IS_RUNNING.get()) {
                    prefs.edit().putBoolean("service_enabled", true).apply();
                    startTunnelService("START");
                } else {
                    startTunnelService("FORCE_SYNC");
                }
                Toast.makeText(MainActivity.this, "Saved & syncing with Admin Panel...", Toast.LENGTH_SHORT).show();
            }
        });

        battBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                requestIgnoreBatteryOptimizations();
            }
        });

        // Logs Card
        LinearLayout logCard = new LinearLayout(this);
        logCard.setOrientation(LinearLayout.VERTICAL);
        logCard.setPadding(dp(14), dp(14), dp(14), dp(14));
        logCard.setBackground(roundedBg(Color.parseColor("#0B1120"), Color.parseColor("#1E293B"), 14));
        LinearLayout.LayoutParams logLp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        logLp.topMargin = dp(14);
        root.addView(logCard, logLp);

        TextView logHdr = new TextView(this);
        logHdr.setText("LIVE TUNNEL LOGS");
        logHdr.setTextColor(Color.parseColor("#94A3B8"));
        logHdr.setTextSize(11);
        logHdr.setTypeface(Typeface.DEFAULT_BOLD);
        logCard.addView(logHdr);

        logTv = new TextView(this);
        logTv.setText("Ready. Enter Backend Server URL and tap START BACKGROUND TUNNEL.");
        logTv.setTextColor(Color.parseColor("#94A3B8"));
        logTv.setTextSize(11);
        logTv.setTypeface(Typeface.MONOSPACE);
        logTv.setPadding(0, dp(8), 0, 0);
        logCard.addView(logTv);

        setContentView(scroll);

        // Auto-start if previously enabled and server_url is configured
        if (prefs.getBoolean("service_enabled", false) && !savedSrvUrl.isEmpty() && !TunnelService.IS_RUNNING.get()) {
            startTunnelService("START");
        }

        uiHandler = new Handler(Looper.getMainLooper());
        uiTicker = new Runnable() {
            @Override
            public void run() {
                refreshUi();
                uiHandler.postDelayed(this, 1000);
            }
        };
        uiHandler.post(uiTicker);
    }

    private EditText addLabeledInput(LinearLayout parent, String label, String val, boolean password) {
        TextView tv = new TextView(this);
        tv.setText(label);
        tv.setTextColor(Color.parseColor("#94A3B8"));
        tv.setTextSize(11);
        tv.setTypeface(Typeface.DEFAULT_BOLD);
        tv.setPadding(0, dp(10), 0, dp(4));
        parent.addView(tv);

        EditText et = new EditText(this);
        et.setText(val);
        et.setTextColor(Color.WHITE);
        et.setHintTextColor(Color.parseColor("#64748B"));
        et.setTextSize(14);
        et.setSingleLine(true);
        if (password) {
            et.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        } else {
            et.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_URI);
        }
        et.setPadding(dp(12), dp(10), dp(12), dp(10));
        et.setBackground(roundedBg(Color.parseColor("#1E293B"), Color.parseColor("#334155"), 10));
        parent.addView(et);
        return et;
    }

    private void saveSettings() {
        SharedPreferences prefs = getSharedPreferences("tdb_tunnel_prefs", MODE_PRIVATE);
        prefs.edit()
                .putString("device_name", devNameInput.getText().toString().trim())
                .putString("server_url", srvUrlInput.getText().toString().trim())
                .putString("secret", secretInput.getText().toString().trim())
                .apply();
    }

    private void startTunnelService(String action) {
        Intent svc = new Intent(this, TunnelService.class);
        svc.setAction(action);
        if (Build.VERSION.SDK_INT >= 26) {
            startForegroundService(svc);
        } else {
            startService(svc);
        }
    }

    private void requestIgnoreBatteryOptimizations() {
        if (Build.VERSION.SDK_INT >= 23) {
            try {
                PowerManager pm = (PowerManager) getSystemService(Context.POWER_SERVICE);
                if (pm != null && !pm.isIgnoringBatteryOptimizations(getPackageName())) {
                    Intent i = new Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS);
                    i.setData(Uri.parse("package:" + getPackageName()));
                    startActivity(i);
                } else {
                    Toast.makeText(this, "24/7 Background execution is already enabled!", Toast.LENGTH_SHORT).show();
                }
            } catch (Exception e) {
                Toast.makeText(this, "Could not open battery settings: " + e.getMessage(), Toast.LENGTH_SHORT).show();
            }
        }
    }

    private void refreshUi() {
        boolean running = TunnelService.IS_RUNNING.get();
        boolean wsOk = TunnelService.WS_CONNECTED.get();
        statusBadge.setText("STATUS: " + TunnelService.STATUS_TEXT.toUpperCase() +
                "  •  REQ: " + TunnelService.TOTAL_CONNS.get());
        statusBadge.setTextColor(wsOk ? Color.parseColor("#34D399") :
                (running ? Color.parseColor("#FBBF24") : Color.parseColor("#F87171")));

        ipInfoTv.setText("Public IP: " + TunnelService.PUBLIC_IP +
                (TunnelService.ISP_INFO.isEmpty() ? "" : " • " + TunnelService.ISP_INFO));

        if (running) {
            toggleBtn.setText("STOP BACKGROUND TUNNEL");
            toggleBtn.setBackground(roundedBg(Color.parseColor("#EF4444"), 0, 12));
        } else {
            toggleBtn.setText("START BACKGROUND TUNNEL");
            toggleBtn.setBackground(roundedBg(Color.parseColor("#10B981"), 0, 12));
        }

        String logs = TunnelService.getLogsText();
        if (!logs.isEmpty()) {
            logTv.setText(logs);
        }
    }

    @Override
    protected void onDestroy() {
        if (uiHandler != null && uiTicker != null) {
            uiHandler.removeCallbacks(uiTicker);
        }
        super.onDestroy();
    }
}
