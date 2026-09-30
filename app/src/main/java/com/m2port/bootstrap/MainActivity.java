package com.m2port.bootstrap;

import android.app.Activity;
import android.os.Bundle;
import android.graphics.Color;
import android.graphics.Typeface;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import java.io.File;

public final class MainActivity extends Activity {
    static { System.loadLibrary("m2bootstrap"); }

    private static native String nativeProbe(String gameRoot);
    private static native String nativeStart(String gameRoot);

    private TextView status;
    private String gameRoot;

    @Override protected void onCreate(Bundle state) {
        super.onCreate(state);
        getWindow().getDecorView().setSystemUiVisibility(
            View.SYSTEM_UI_FLAG_IMMERSIVE_STICKY |
            View.SYSTEM_UI_FLAG_FULLSCREEN |
            View.SYSTEM_UI_FLAG_HIDE_NAVIGATION);

        File root = new File(getExternalFilesDir(null), "Mafia2");
        if (!root.exists()) root.mkdirs();
        gameRoot = root.getAbsolutePath();

        LinearLayout page = new LinearLayout(this);
        page.setOrientation(LinearLayout.VERTICAL);
        page.setPadding(28, 24, 28, 24);
        page.setBackgroundColor(Color.rgb(8, 10, 13));

        TextView title = new TextView(this);
        title.setText("MAFIA II • ANDROID ARM64");
        title.setTextColor(Color.WHITE);
        title.setTextSize(23f);
        title.setTypeface(Typeface.DEFAULT_BOLD);
        page.addView(title);

        TextView subtitle = new TextView(this);
        subtitle.setText("Native host / recomp path");
        subtitle.setTextColor(Color.LTGRAY);
        subtitle.setTextSize(14f);
        subtitle.setPadding(0, 4, 0, 18);
        page.addView(subtitle);

        status = new TextView(this);
        status.setTextColor(Color.rgb(215, 224, 232));
        status.setTextSize(14f);
        status.setTypeface(Typeface.MONOSPACE);
        status.setTextIsSelectable(true);
        page.addView(status, new LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f));

        LinearLayout actions = new LinearLayout(this);
        actions.setOrientation(LinearLayout.HORIZONTAL);
        actions.setGravity(Gravity.CENTER_VERTICAL);

        Button refresh = new Button(this);
        refresh.setText("CHECK");
        refresh.setOnClickListener(v -> refreshStatus());
        actions.addView(refresh, new LinearLayout.LayoutParams(0,
            LinearLayout.LayoutParams.WRAP_CONTENT, 1f));

        Button launch = new Button(this);
        launch.setText("START MAFIA II");
        launch.setOnClickListener(v -> status.setText(nativeStart(gameRoot)));
        actions.addView(launch, new LinearLayout.LayoutParams(0,
            LinearLayout.LayoutParams.WRAP_CONTENT, 1f));

        page.addView(actions);

        ScrollView scroller = new ScrollView(this);
        scroller.addView(page);
        setContentView(scroller);
        refreshStatus();
    }

    private void refreshStatus() {
        status.setText(nativeProbe(gameRoot));
    }
}
